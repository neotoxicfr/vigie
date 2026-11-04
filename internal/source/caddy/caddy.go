// Package caddy découvre les routes HTTP d'une instance Caddy par son API
// d'administration (GET /config/), en lecture seule.
package caddy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/source"
)

type Caddy struct {
	name, base string
	client     *http.Client
}

func New(name, adminURL string) *Caddy {
	return &Caddy{name, strings.TrimRight(adminURL, "/"), &http.Client{Timeout: 15 * time.Second}}
}

func (c *Caddy) Name() string { return "caddy/" + c.name }

const (
	maxBody    = 16 << 20
	maxDepth   = 16
	maxAllowed = 4096 // préfixes d'une liste déduite d'une liste de refus
)

type config struct {
	Apps struct {
		HTTP struct {
			Servers map[string]server `json:"servers"`
		} `json:"http"`
	} `json:"apps"`
}

type server struct {
	Listen    []string   `json:"listen"`
	Routes    []rawRoute `json:"routes"`
	AutoHTTPS *struct {
		Disable      bool     `json:"disable"`
		DisableCerts bool     `json:"disable_certificates"`
		Skip         []string `json:"skip"`
		SkipCerts    []string `json:"skip_certificates"`
	} `json:"automatic_https"`
	Policies []json.RawMessage `json:"tls_connection_policies"`
}

type rawRoute struct {
	Match  []map[string]json.RawMessage `json:"match"`
	Handle []json.RawMessage            `json:"handle"`
}

func (c *Caddy) Discover(ctx context.Context) ([]source.Route, error) {
	body, err := c.get(ctx, c.base+"/config/")
	if err != nil {
		return nil, fmt.Errorf("%s : %w", c.Name(), err)
	}
	var cfg config
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, fmt.Errorf("%s : JSON invalide : %w", c.Name(), err)
	}
	names := make([]string, 0, len(cfg.Apps.HTTP.Servers))
	for n := range cfg.Apps.HTTP.Servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []source.Route
	for _, n := range names {
		w := &walker{src: c.Name(), srv: n, s: cfg.Apps.HTTP.Servers[n], used: map[string]int{}}
		w.ports()
		w.routes(w.s.Routes, state{}, 0)
		out = append(out, w.out...)
	}
	return out, nil
}

func (c *Caddy) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s : %s", redact(u), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("GET %s : réponse > %d octets", redact(u), maxBody)
	}
	return b, nil
}

func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "?"
	}
	return p.Redacted()
}

// guard est un middleware qui ne vaut que pour certains hôtes/chemins (garde
// posée par une route sœur plus haut dans la liste).
type guard struct {
	mw         source.Middleware
	hosts      []string
	paths      []string
	declaredAs string
	problem    string
}

// state est le contexte hérité en descendant : matchers cumulés et middlewares
// déjà appliqués. Les slices sont copiées avant toute modification.
type state struct {
	hosts   []string
	hostSet bool
	wild    bool // host à joker : HTTPS automatique quand même
	paths   []string
	guards  []guard
	probs   []string
}

func (s state) addGuard(g guard) state {
	s.guards = append(slices.Clone(s.guards), g)
	return s
}

func (s state) addProb(p string) state {
	if !slices.Contains(s.probs, p) {
		s.probs = append(slices.Clone(s.probs), p)
	}
	return s
}

type walker struct {
	src, srv string
	s        server
	used     map[string]int
	ports_   []int
	out      []source.Route
}

// ports extrait les ports TCP de listen ("[réseau/]hôte:port[-port]").
func (w *walker) ports() {
	for _, l := range w.s.Listen {
		if i := strings.Index(l, "/"); i >= 0 {
			if n := l[:i]; !strings.HasPrefix(n, "tcp") {
				continue // udp (HTTP/3 sur le même port), unix, fd…
			}
			l = l[i+1:]
		}
		_, p, err := net.SplitHostPort(l)
		if err != nil {
			continue
		}
		lo, hi, isRange := strings.Cut(p, "-")
		a, err1 := strconv.Atoi(lo)
		b := a
		if isRange {
			b, _ = strconv.Atoi(hi)
		}
		if err1 != nil || a < 1 || b < a || b-a > 64 {
			continue
		}
		for n := a; n <= b; n++ {
			if !slices.Contains(w.ports_, n) {
				w.ports_ = append(w.ports_, n)
			}
		}
	}
	sort.Ints(w.ports_)
}

// matchSet est un jeu de matchers (ET) d'une route.
type matchSet struct {
	hosts, paths []string
	hasHost      bool
	wild         bool
	probs        []string
	// ip : plages de remote_ip/client_ip ; neg : sous un not.
	ip, ipNot       []netip.Prefix
	hasIP, hasIPNot bool
	other           bool // autre matcher non analysé
	cond            bool // matcher hors host/path/remote_ip/client_ip/not (méthode, en-tête…)
	raw             map[string]json.RawMessage
}

var harmlessMatchers = map[string]bool{"method": true, "protocol": true, "header": true, "query": true, "vars": true, "file": true, "tls": true}

func parseSet(m map[string]json.RawMessage) matchSet {
	ms := matchSet{raw: m}
	for k, v := range m {
		switch k {
		case "host":
			var hs []string
			json.Unmarshal(v, &hs)
			ms.hasHost = true
			for _, h := range hs {
				h = strings.ToLower(strings.TrimSpace(h))
				if strings.ContainsAny(h, "*{}") {
					ms.wild = true
					ms.probs = append(ms.probs, "host non littéral ignoré : "+h)
				} else if h != "" {
					ms.hosts = append(ms.hosts, h)
				}
			}
		case "path":
			json.Unmarshal(v, &ms.paths)
		case "remote_ip", "client_ip":
			ms.hasIP = true
			ms.ip = append(ms.ip, parseRanges(v)...)
		case "not":
			var sets []map[string]json.RawMessage
			json.Unmarshal(v, &sets)
			for _, s := range sets {
				sub := parseSet(s)
				if sub.hasIP && !sub.hasHost && len(sub.paths) == 0 && !sub.other && !sub.cond && !sub.hasIPNot {
					ms.hasIPNot = true
					ms.ipNot = append(ms.ipNot, sub.ip...)
				} else {
					ms.other = true
					// IP mêlée à d'autres conditions : garde quand même, mais non interprétée.
					ms.hasIPNot = ms.hasIPNot || sub.hasIP || sub.hasIPNot
				}
			}
		default:
			ms.cond = true
			if !harmlessMatchers[k] {
				ms.other = true
				ms.probs = append(ms.probs, "matcher "+k+" non analysé")
			}
		}
	}
	return ms
}

func parseRanges(v json.RawMessage) []netip.Prefix {
	var r struct {
		Ranges []string `json:"ranges"`
	}
	json.Unmarshal(v, &r)
	var out []netip.Prefix
	for _, s := range r.Ranges {
		if s == "private_ranges" {
			for _, p := range []string{"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.0/8", "fd00::/8", "::1/128"} {
				out = append(out, netip.MustParsePrefix(p))
			}
			continue
		}
		if p, err := parsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// narrow applique un jeu de matchers au contexte ; ok=false si la route est inatteignable.
func (s state) narrow(m matchSet) (state, bool) {
	for _, p := range m.probs {
		s = s.addProb(p)
	}
	s.wild = s.wild || m.wild
	if m.hasHost {
		if s.hostSet {
			var keep []string
			for _, h := range m.hosts {
				if slices.Contains(s.hosts, h) {
					keep = append(keep, h)
				}
			}
			if len(keep) == 0 && len(m.hosts) > 0 && len(s.hosts) > 0 {
				return s, false
			}
			s.hosts = keep
		} else {
			s.hosts = slices.Clone(m.hosts)
		}
		s.hostSet = true
	}
	if len(m.paths) > 0 {
		s.paths = slices.Clone(m.paths)
	}
	return s, true
}

type handler struct {
	Handler string `json:"handler"`
}

func (w *walker) routes(routes []rawRoute, s state, depth int) {
	if depth > maxDepth {
		return
	}
	acc := s
	for _, r := range routes {
		sets := r.Match
		if len(sets) == 0 {
			sets = []map[string]json.RawMessage{nil}
		}
		for _, raw := range sets {
			ms := parseSet(raw)
			if g, ok := guardOf(ms, r); ok {
				acc = acc.addGuard(g)
				continue
			}
			br, ok := acc.narrow(ms)
			if !ok {
				continue
			}
			after, _ := w.handles(r.Handle, br, depth)
			// Les middlewares d'une route sans matcher d'hôte ni de chemin valent pour la suite.
			if !ms.hasHost && len(ms.paths) == 0 && !ms.other && !ms.cond {
				acc.guards = after.guards
			}
		}
	}
}

// guardOf reconnaît une route de refus conditionnée par l'IP : le refus d'une
// liste (remote_ip → 403) ou d'un complément (not remote_ip → 403).
func guardOf(ms matchSet, r rawRoute) (guard, bool) {
	if (!ms.hasIP && !ms.hasIPNot) || len(r.Handle) == 0 {
		return guard{}, false
	}
	for _, h := range r.Handle {
		if !isDeny(h) {
			return guard{}, false
		}
	}
	g := guard{hosts: ms.hosts, paths: ms.paths, declaredAs: "remote_ip"}
	raw, _ := json.Marshal(ms.raw)
	g.mw = source.Middleware{Name: "remote_ip", Type: "remote_ip", Kind: source.Other, Config: raw}
	switch {
	case ms.cond || ms.other:
		// Ex. refus limité à POST : le reste passe, ce n'est pas une liste blanche.
		g.problem = "garde IP conditionnelle, non interprétée"
	case ms.hasIP && ms.hasIPNot:
		g.problem = "garde IP non analysée (matchers combinés)"
	case ms.hasIPNot: // refus hors des plages : elles sont les autorisées
		g.mw.Kind = source.IPAllow
		g.mw.AllowFrom = dedupe(ms.ipNot)
	default: // refus des plages : autorisées = complément
		g.mw.Kind = source.IPAllow
		al, ok := complement(ms.ip)
		if !ok {
			g.mw.Kind = source.Other
			g.problem = "liste de refus IP trop fragmentée pour en déduire les autorisées"
		}
		g.mw.AllowFrom = al
	}
	if len(ms.paths) > 0 {
		g.problem = "garde IP limitée à certains chemins"
	}
	return g, true
}

func isDeny(h json.RawMessage) bool {
	var d struct {
		Handler string          `json:"handler"`
		Status  json.RawMessage `json:"status_code"`
		Abort   bool            `json:"abort"`
		Close   bool            `json:"close"`
	}
	json.Unmarshal(h, &d)
	switch d.Handler {
	case "error":
		return true
	case "static_response":
		if d.Abort || d.Close {
			return true
		}
		n, _ := strconv.Atoi(strings.Trim(string(d.Status), `"`))
		return n >= 400
	}
	return false
}

func dedupe(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// complement renvoie l'espace IPv4+IPv6 privé des plages refusées.
func complement(deny []netip.Prefix) ([]netip.Prefix, bool) {
	cur := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, d := range deny {
		var next []netip.Prefix
		for _, c := range cur {
			next = append(next, subtract(c, d)...)
			if len(next) > maxAllowed {
				return nil, false
			}
		}
		cur = next
	}
	return cur, true
}

// subtract retire d de c en découpant c en moitiés.
func subtract(c, d netip.Prefix) []netip.Prefix {
	if c.Addr().Is4() != d.Addr().Is4() || !c.Overlaps(d) {
		return []netip.Prefix{c}
	}
	if d.Bits() <= c.Bits() {
		return nil
	}
	lo := netip.PrefixFrom(c.Addr(), c.Bits()+1)
	hi := netip.PrefixFrom(flipBit(c.Addr(), c.Bits()), c.Bits()+1)
	return append(subtract(lo, d), subtract(hi, d)...)
}

func flipBit(a netip.Addr, bit int) netip.Addr {
	b := a.AsSlice()
	b[bit/8] |= 0x80 >> (bit % 8)
	r, _ := netip.AddrFromSlice(b)
	return r
}

type proxyH struct {
	Upstreams []struct {
		Dial string `json:"dial"`
	} `json:"upstreams"`
	Dynamic        json.RawMessage   `json:"dynamic_upstreams"`
	HandleResponse []json.RawMessage `json:"handle_response"`
	Rewrite        struct {
		URI string `json:"uri"`
	} `json:"rewrite"`
	Transport struct {
		Protocol string          `json:"protocol"`
		TLS      json.RawMessage `json:"tls"`
	} `json:"transport"`
}

func (p proxyH) urls() []string {
	scheme := "http://"
	switch {
	case p.Transport.Protocol == "fastcgi":
		scheme = "fastcgi://"
	case len(p.Transport.TLS) > 0 && string(p.Transport.TLS) != "null":
		scheme = "https://"
	}
	var out []string
	for _, u := range p.Upstreams {
		if u.Dial == "" {
			continue
		}
		if strings.Contains(u.Dial, "://") || strings.HasPrefix(u.Dial, "unix/") {
			out = append(out, u.Dial)
		} else {
			out = append(out, scheme+u.Dial)
		}
	}
	return out
}

// handles déroule les handlers d'une route dans l'ordre ; renvoie l'état après
// eux et true si l'un a terminé la requête (contenu produit).
func (w *walker) handles(hs []json.RawMessage, s state, depth int) (state, bool) {
	var local []source.Middleware
	var declared []string
	for _, raw := range hs {
		var h handler
		json.Unmarshal(raw, &h)
		switch h.Handler {
		case "subroute":
			var sr struct {
				Routes []rawRoute `json:"routes"`
			}
			json.Unmarshal(raw, &sr)
			// Les middlewares locaux déjà vus valent pour la sous-route.
			sub := s
			for _, m := range local {
				sub = sub.addGuard(guard{mw: m, declaredAs: m.Name})
			}
			w.routes(sr.Routes, sub, depth+1)
			return s, true
		case "reverse_proxy":
			var p proxyH
			json.Unmarshal(raw, &p)
			if fa, ok := forwardAuth(p, raw); ok {
				local = append(local, fa)
				declared = append(declared, "forward_auth")
				continue
			}
			rt := w.emit(s, local, declared)
			rt.Backends = p.urls()
			if len(p.Dynamic) > 0 && string(p.Dynamic) != "null" {
				rt.Problems = append(rt.Problems, "upstreams dynamiques : backends non listés")
			}
			w.out = append(w.out, rt)
			return s, true
		case "file_server":
			w.out = append(w.out, w.emit(s, local, declared))
			return s, true
		case "static_response":
			if isDeny(raw) {
				return s, true
			}
			rt := w.emit(s, local, declared)
			var sr struct {
				Status  json.RawMessage     `json:"status_code"`
				Headers map[string][]string `json:"headers"`
			}
			json.Unmarshal(raw, &sr)
			n, _ := strconv.Atoi(strings.Trim(string(sr.Status), `"`))
			if loc := headerGet(sr.Headers, "Location"); loc != "" && n >= 300 && n < 400 {
				rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "redir", Type: "static_response", Kind: source.Redirect, Config: raw})
				rt.Declared = append(rt.Declared, "redir")
			}
			w.out = append(w.out, rt)
			return s, true
		}
		if m, name, ok := convert(h.Handler, raw); ok {
			local = append(local, m)
			declared = append(declared, name)
		}
	}
	for _, m := range local {
		s = s.addGuard(guard{mw: m, declaredAs: m.Name})
	}
	return s, false
}

func headerGet(h map[string][]string, k string) string {
	for n, v := range h {
		if strings.EqualFold(n, k) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

var passive = map[string]bool{"encode": true, "vars": true, "rewrite": true, "log_append": true, "map": true,
	"templates": true, "copy_response": true, "copy_response_headers": true, "intercept": true, "push": true,
	"tracing": true, "invoke": true, "request_body": true, "metrics": true}

// convert classe un handler non terminal en middleware.
func convert(name string, raw json.RawMessage) (source.Middleware, string, bool) {
	m := source.Middleware{Name: name, Type: name, Kind: source.Other, Config: raw}
	switch name {
	case "headers":
		m.Kind = source.Headers
	case "rate_limit", "ratelimit":
		m.Kind = source.RateLimit
	case "authentication":
		var a struct {
			Providers map[string]json.RawMessage `json:"providers"`
		}
		json.Unmarshal(raw, &a)
		if _, ok := a.Providers["http_basic"]; ok && len(a.Providers) == 1 {
			m.Kind, m.Type = source.BasicAuth, "http_basic"
		}
	default:
		if passive[name] || name == "" {
			return m, "", false
		}
	}
	return m, name, true
}

// forwardAuth reconnaît l'expansion JSON de la directive forward_auth : un
// reverse_proxy dont handle_response prend la main sur les réponses 2xx.
func forwardAuth(p proxyH, raw json.RawMessage) (source.Middleware, bool) {
	if len(p.HandleResponse) == 0 || len(p.Upstreams) == 0 {
		return source.Middleware{}, false
	}
	ok := false
	for _, hr := range p.HandleResponse {
		var r struct {
			Match struct {
				Status []int `json:"status_code"`
			} `json:"match"`
		}
		json.Unmarshal(hr, &r)
		if slices.Contains(r.Match.Status, 2) {
			ok = true
		}
	}
	if !ok {
		return source.Middleware{}, false
	}
	u := p.urls()
	return source.Middleware{Name: "forward_auth", Type: "reverse_proxy", Kind: source.ForwardAuth,
		AuthURL: strings.Join(u[:min(1, len(u))], "") + p.Rewrite.URI, Config: raw}, true
}

// emit construit la Route d'un contenu terminal avec le contexte et les middlewares cumulés.
func (w *walker) emit(s state, local []source.Middleware, declared []string) source.Route {
	rt := source.Route{Source: w.src, Hosts: slices.Clone(s.hosts), Paths: slices.Clone(s.paths),
		Ports: slices.Clone(w.ports_), Problems: slices.Clone(s.probs), Declared: declared}
	if !s.hostSet || len(s.hosts) == 0 && len(s.probs) == 0 {
		rt.Problems = append(rt.Problems, "aucun host littéral dans les matchers : hôtes non scannables")
	}
	for _, g := range s.guards {
		if len(g.hosts) > 0 && len(s.hosts) > 0 && !slices.ContainsFunc(s.hosts, func(h string) bool { return slices.Contains(g.hosts, h) }) {
			continue
		}
		rt.Middlewares = append(rt.Middlewares, g.mw)
		if g.problem != "" {
			rt.Problems = append(rt.Problems, g.problem)
		}
		if g.declaredAs != "" {
			rt.Declared = append(rt.Declared, g.declaredAs)
		}
	}
	rt.Middlewares = append(rt.Middlewares, local...)
	rt.TLS = w.tls(s.hosts, s.wild)
	first := "*"
	if len(rt.Hosts) > 0 {
		first = rt.Hosts[0]
	}
	base := w.srv + "/" + first
	w.used[base]++
	rt.Name = base
	if n := w.used[base]; n > 1 {
		rt.Name += "#" + strconv.Itoa(n)
	}
	return rt
}

// tls : politique TLS explicite, sinon HTTPS automatique de Caddy pour un nom
// public (hors port 80, hors listes d'exclusion).
func (w *walker) tls(hosts []string, wild bool) bool {
	if len(w.s.Policies) > 0 {
		return true
	}
	a := w.s.AutoHTTPS
	if a != nil && (a.Disable || a.DisableCerts) {
		return false
	}
	if len(w.ports_) == 1 && w.ports_[0] == 80 {
		return false
	}
	if wild {
		return true
	}
	for _, h := range hosts {
		if autoName(h) && (a == nil || !slices.Contains(a.Skip, h) && !slices.Contains(a.SkipCerts, h)) {
			return true
		}
	}
	return false
}

// autoName : noms pour lesquels Caddy ne gère pas de certificat (IP, locaux).
func autoName(h string) bool {
	if _, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		return false
	}
	if h == "localhost" {
		return false
	}
	for _, suf := range []string{".localhost", ".local", ".internal", ".home.arpa"} {
		if strings.HasSuffix(h, suf) {
			return false
		}
	}
	return true
}
