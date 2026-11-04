// Package nginx découvre les routes d'une configuration nginx lue sur disque
// (nginx.conf et ses include, confinés au dossier), en lecture seule.
package nginx

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/neotoxicfr/vigie/internal/source"
)

type Nginx struct{ name, dir string }

func New(name, dir string) *Nginx { return &Nginx{name, dir} }

func (n *Nginx) Name() string { return "nginx/" + n.name }

func (n *Nginx) Discover(ctx context.Context) ([]source.Route, error) {
	top, err := loadDir(n.dir)
	if err != nil {
		return nil, errf(n.Name(), err)
	}
	var out []source.Route
	used := map[string]int{}
	for _, h := range top {
		if h.name != "http" || !h.block {
			continue
		}
		b := &builder{src: n.Name(), upstreams: map[string][]string{}, used: used}
		b.collectUpstreams(h.kids)
		base := inherit(access{}, h.kids)
		for _, s := range h.kids {
			if s.name == "server" && s.block {
				out = append(out, b.server(s, base)...)
			}
		}
	}
	return out, nil
}

type wrapped struct {
	pre string
	err error
}

func (w wrapped) Error() string { return w.pre + " : " + w.err.Error() }
func (w wrapped) Unwrap() error { return w.err }

func errf(pre string, err error) error { return wrapped{pre, err} }

type rule struct {
	allow bool
	pfx   []netip.Prefix // « all » donne les deux familles
}

type hdr struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Always bool   `json:"always,omitempty"`
}

// access est l'état hérité (http → server → location) des directives d'accès.
type access struct {
	rules    []rule
	hasRules bool
	basic    string // "" : aucune ; sinon le domaine
	authReq  string
	satisfy  string
	headers  []hdr
	limits   [][]string
}

func (a access) sig() string {
	b, _ := json.Marshal([]any{a.rules, a.basic, a.authReq, a.satisfy})
	return string(b)
}

// inherit applique les directives d'un bloc : celles qu'il pose remplacent
// l'héritage (allow/deny, add_header et limit_* par jeu complet, les autres une à une).
func inherit(a access, kids []*node) access {
	var rules []rule
	var hs []hdr
	var lims [][]string
	for _, k := range kids {
		switch k.name {
		case "allow", "deny":
			if len(k.args) == 1 {
				rules = append(rules, rule{k.name == "allow", parseAddr(k.args[0])})
			}
		case "auth_basic":
			if len(k.args) == 1 {
				a.basic = ""
				if k.args[0] != "off" {
					a.basic = k.args[0]
				}
			}
		case "auth_request":
			if len(k.args) == 1 {
				a.authReq = ""
				if k.args[0] != "off" {
					a.authReq = k.args[0]
				}
			}
		case "satisfy":
			if len(k.args) == 1 {
				a.satisfy = k.args[0]
			}
		case "add_header":
			if len(k.args) >= 2 {
				hs = append(hs, hdr{k.args[0], k.args[1], len(k.args) > 2 && k.args[2] == "always"})
			}
		case "limit_req", "limit_conn":
			lims = append(lims, append([]string{k.name}, k.args...))
		}
	}
	if len(rules) > 0 {
		a.rules, a.hasRules = rules, true
	}
	if len(hs) > 0 {
		a.headers = hs
	}
	if len(lims) > 0 {
		a.limits = lims
	}
	return a
}

func parseAddr(s string) []netip.Prefix {
	if s == "all" {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	if strings.Contains(s, "/") {
		if p, err := netip.ParsePrefix(s); err == nil {
			return []netip.Prefix{p.Masked()}
		}
		return nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
	}
	return nil // unix:, nom…
}

const maxAllowed = 4096

// allowed déduit les adresses autorisées de la suite ordonnée allow/deny
// (première règle qui correspond ; défaut : autorisé). ok=false si la liste
// est trop fragmentée ; restricted=false si tout est autorisé.
func allowed(rules []rule) (list []netip.Prefix, restricted, ok bool) {
	rem := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	var acc []netip.Prefix
	denied := false
	for _, r := range rules {
		for _, p := range r.pfx {
			var next []netip.Prefix
			for _, c := range rem {
				if c.Addr().Is4() == p.Addr().Is4() && c.Overlaps(p) {
					if r.allow {
						acc = append(acc, smaller(c, p))
					} else {
						denied = true
					}
				}
				next = append(next, subtract(c, p)...)
			}
			if rem = next; len(rem)+len(acc) > maxAllowed {
				return nil, true, false
			}
		}
	}
	acc = append(acc, rem...)
	return merge(acc), denied, true
}

func smaller(a, b netip.Prefix) netip.Prefix {
	if a.Bits() > b.Bits() {
		return a
	}
	return b
}

// merge retire les préfixes inclus dans un autre.
func merge(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for i, p := range in {
		dup := false
		for j, q := range in {
			if i != j && q.Addr().Is4() == p.Addr().Is4() && q.Bits() <= p.Bits() && q.Contains(p.Addr()) && (q.Bits() < p.Bits() || j < i) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, p)
		}
	}
	return out
}

func subtract(c, d netip.Prefix) []netip.Prefix {
	if c.Addr().Is4() != d.Addr().Is4() || !c.Overlaps(d) {
		return []netip.Prefix{c}
	}
	if d.Bits() <= c.Bits() {
		return nil
	}
	lo := netip.PrefixFrom(c.Addr(), c.Bits()+1)
	b := c.Addr().AsSlice()
	b[c.Bits()/8] |= 0x80 >> (c.Bits() % 8)
	a, _ := netip.AddrFromSlice(b)
	return append(subtract(lo, d), subtract(netip.PrefixFrom(a, c.Bits()+1), d)...)
}

type builder struct {
	src       string
	upstreams map[string][]string
	used      map[string]int
	locs      []locTarget // locations du serveur en cours, pour auth_request
}

type locTarget struct{ mod, match, target string }

func (b *builder) collectUpstreams(ns []*node) {
	for _, n := range ns {
		if n.name == "upstream" && len(n.args) == 1 {
			for _, k := range n.kids {
				if k.name == "server" && len(k.args) > 0 {
					b.upstreams[n.args[0]] = append(b.upstreams[n.args[0]], k.args[0])
				}
			}
		}
	}
}

var passDirectives = map[string]string{"proxy_pass": "", "fastcgi_pass": "fastcgi://", "grpc_pass": "",
	"uwsgi_pass": "uwsgi://", "scgi_pass": "scgi://"}

// backends donne les URL visées par les *_pass d'un bloc, upstream résolu.
func (b *builder) backends(kids []*node) (urls, probs []string) {
	for _, k := range kids {
		pre, ok := passDirectives[k.name]
		if !ok || len(k.args) != 1 {
			continue
		}
		t := k.args[0]
		if strings.Contains(t, "$") {
			probs = append(probs, k.name+" dynamique ("+t+") : backend non résolu")
			continue
		}
		scheme := pre
		host := t
		if i := strings.Index(t, "://"); i >= 0 {
			scheme, host = t[:i+3], t[i+3:]
		} else if scheme == "" {
			scheme = "http://"
		}
		if k.name == "grpc_pass" && scheme == "http://" {
			scheme = "grpc://"
		}
		host = strings.SplitN(host, "/", 2)[0]
		if servers, ok := b.upstreams[host]; ok {
			for _, s := range servers {
				urls = append(urls, scheme+s)
			}
			continue
		}
		urls = append(urls, scheme+host)
	}
	return
}

type listen struct {
	port int
	tls  bool
}

func parseListen(ns []*node) (ls []listen, probs []string) {
	for _, n := range ns {
		if n.name != "listen" || len(n.args) == 0 {
			continue
		}
		a := n.args[0]
		if strings.HasPrefix(a, "unix:") {
			continue
		}
		port := 80
		if i := strings.LastIndex(a, ":"); i >= 0 && !strings.HasSuffix(a, "]") {
			a = a[i+1:]
		} else if strings.HasSuffix(a, "]") {
			a = ""
		}
		if a != "" {
			p, err := strconv.Atoi(a)
			if err != nil {
				// « localhost », « *:80 »… : un nom sans port vaut 80
				if strings.Contains(n.args[0], ":") {
					probs = append(probs, "listen illisible : "+n.args[0])
					continue
				}
			} else {
				port = p
			}
		}
		l := listen{port: port}
		for _, f := range n.args[1:] {
			if f == "ssl" || f == "quic" {
				l.tls = true
			}
		}
		ls = append(ls, l)
	}
	return
}

func hasDirective(ns []*node, name string) bool {
	return slices.ContainsFunc(ns, func(n *node) bool { return n.name == name })
}

func (b *builder) server(s *node, parent access) []source.Route {
	acc := inherit(parent, s.kids)
	ls, probs := parseListen(s.kids)
	if len(ls) == 0 {
		ls = []listen{{port: 80}}
	}
	if hasDirective(s.kids, "ssl") && slices.ContainsFunc(s.kids, func(n *node) bool { return n.name == "ssl" && len(n.args) == 1 && n.args[0] == "on" }) {
		for i := range ls {
			ls[i].tls = true
		}
	}
	var ports []int
	tls := false
	for _, l := range ls {
		if !slices.Contains(ports, l.port) {
			ports = append(ports, l.port)
		}
		tls = tls || l.tls
	}
	sort.Ints(ports)

	var hosts []string
	var first string
	for _, k := range s.kids {
		if k.name != "server_name" {
			continue
		}
		for _, h := range k.args {
			if first == "" {
				first = h
			}
			h = strings.ToLower(h)
			switch {
			case h == "_" || h == "":
			case strings.HasPrefix(h, "~") || strings.ContainsAny(h, "*$") || strings.HasPrefix(h, ".") || strings.HasSuffix(h, "."):
				probs = append(probs, "server_name non littéral ignoré : "+h)
			default:
				if !slices.Contains(hosts, h) {
					hosts = append(hosts, h)
				}
			}
		}
	}
	if len(hosts) == 0 {
		probs = append(probs, "aucun server_name littéral : hôtes non scannables")
	}
	if first == "" {
		first = "_"
	}
	name := first + ":" + strconv.Itoa(ls[0].port)
	b.used[b.src+name]++
	if n := b.used[b.src+name]; n > 1 {
		name += "#" + strconv.Itoa(n)
	}

	b.locs = nil
	b.collectLocs(s.kids)
	base := source.Route{Source: b.src, Hosts: hosts, Ports: ports, TLS: tls}
	srvRoute := base
	srvRoute.Name = name
	srvRoute.Rule = "server"
	srvRoute.Problems = probs
	b.fill(&srvRoute, acc)
	routes := []source.Route{srvRoute}
	srvSig := acc.sig()
	var shared []string
	var visit func(kids []*node, parent access)
	visit = func(kids []*node, parent access) {
		for _, l := range kids {
			if l.name != "location" || !l.block || len(l.args) == 0 || hasDirective(l.kids, "internal") {
				continue
			}
			la := inherit(parent, l.kids)
			urls, bp := b.backends(l.kids)
			if la.sig() == srvSig {
				shared = append(shared, urls...)
				routes[0].Problems = appendNew(routes[0].Problems, bp...)
				if p := l.args[len(l.args)-1]; p == "/" {
					for _, m := range redirects(l.kids) {
						routes[0].Middlewares = append(routes[0].Middlewares, m)
						routes[0].Declared = appendNew(routes[0].Declared, "return")
					}
				}
			} else {
				r := base
				r.Rule = "location " + strings.Join(l.args, " ")
				r.Name = name + " " + r.Rule
				r.Backends = urls
				r.Problems = append(slices.Clone(probs), bp...)
				mod, match := "", l.args[len(l.args)-1]
				if len(l.args) > 1 {
					mod = l.args[0]
				}
				if mod == "~" || mod == "~*" {
					r.Problems = append(r.Problems, "location regex non analysée : "+match)
				} else {
					r.Paths = []string{match}
				}
				b.fill(&r, la)
				for _, m := range redirects(l.kids) {
					r.Middlewares = append(r.Middlewares, m)
					r.Declared = appendNew(r.Declared, "return")
				}
				routes = append(routes, r)
			}
			visit(l.kids, la)
		}
	}
	visit(s.kids, acc)
	for _, u := range shared {
		routes[0].Backends = appendNew(routes[0].Backends, u)
	}
	// Redirections posées au niveau du serveur (return, ou return sous un if).
	for _, m := range redirects(s.kids) {
		routes[0].Middlewares = append(routes[0].Middlewares, m)
		routes[0].Declared = appendNew(routes[0].Declared, "return")
	}
	for _, k := range s.kids {
		if k.name == "if" {
			for _, m := range redirects(k.kids) {
				m.Name = "return (if " + strings.Join(k.args, " ") + ")"
				routes[0].Middlewares = append(routes[0].Middlewares, m)
				routes[0].Declared = appendNew(routes[0].Declared, "return")
			}
		}
	}
	return routes
}

func appendNew(l []string, add ...string) []string {
	for _, a := range add {
		if !slices.Contains(l, a) {
			l = append(l, a)
		}
	}
	return l
}

// fill pose sur la route les middlewares déduits de l'accès hérité.
func (b *builder) fill(r *source.Route, a access) {
	raw := func(v any) json.RawMessage { j, _ := json.Marshal(v); return j }
	ipRestricted := false
	if a.hasRules {
		r.Declared = append(r.Declared, "allow/deny")
		list, restricted, ok := allowed(a.rules)
		ipRestricted = restricted
		switch {
		case !ok:
			r.Problems = append(r.Problems, "liste allow/deny trop fragmentée pour en déduire les adresses autorisées")
			r.Middlewares = append(r.Middlewares, source.Middleware{Name: "allow/deny", Type: "allow/deny", Kind: source.Other, Config: raw(a.rules)})
		case restricted:
			r.Middlewares = append(r.Middlewares, source.Middleware{Name: "allow/deny", Type: "allow/deny", Kind: source.IPAllow,
				AllowFrom: list, Config: raw(map[string]any{"rules": ruleStrings(a.rules), "satisfy": a.satisfy})})
		}
	}
	authed := false
	if a.basic != "" {
		authed = true
		r.Declared = append(r.Declared, "auth_basic")
		r.Middlewares = append(r.Middlewares, source.Middleware{Name: "auth_basic", Type: "auth_basic", Kind: source.BasicAuth,
			Config: raw(map[string]string{"realm": a.basic})})
	}
	if a.authReq != "" {
		authed = true
		r.Declared = append(r.Declared, "auth_request")
		r.Middlewares = append(r.Middlewares, source.Middleware{Name: "auth_request", Type: "auth_request", Kind: source.ForwardAuth,
			AuthURL: b.authTarget(a.authReq), Config: raw(map[string]string{"uri": a.authReq})})
	}
	if a.satisfy == "any" && ipRestricted && authed {
		for i := range r.Middlewares {
			if r.Middlewares[i].Type == "allow/deny" && r.Middlewares[i].Kind == source.IPAllow {
				r.Middlewares[i].OrAuth = true
			}
		}
		r.Problems = append(r.Problems, "satisfy any : l'adresse OU l'authentification suffit")
	}
	if len(a.headers) > 0 {
		r.Declared = append(r.Declared, "add_header")
		r.Middlewares = append(r.Middlewares, source.Middleware{Name: "add_header", Type: "add_header", Kind: source.Headers, Config: raw(a.headers)})
	}
	if len(a.limits) > 0 {
		r.Declared = append(r.Declared, "limit_req")
		r.Middlewares = append(r.Middlewares, source.Middleware{Name: "limit_req", Type: "limit_req", Kind: source.RateLimit, Config: raw(a.limits)})
	}
}

func ruleStrings(rs []rule) []string {
	var out []string
	for _, r := range rs {
		verb := "deny"
		if r.allow {
			verb = "allow"
		}
		out = append(out, verb+" "+prefixes(r.pfx))
	}
	return out
}

func prefixes(ps []netip.Prefix) string {
	if len(ps) == 2 && ps[0].Bits() == 0 && ps[1].Bits() == 0 {
		return "all"
	}
	var s []string
	for _, p := range ps {
		s = append(s, p.String())
	}
	return strings.Join(s, ",")
}

// authTarget : proxy_pass de la location interne visée par auth_request, sinon l'URI.
// L'URI est cherchée dans tout le serveur, hors de la location courante.
func (b *builder) authTarget(uri string) string {
	best, target := -1, ""
	for _, l := range b.locs {
		if l.target == "" || l.mod == "~" || l.mod == "~*" || !strings.HasPrefix(uri, l.match) || (l.mod == "=" && uri != l.match) {
			continue
		}
		if len(l.match) > best {
			best, target = len(l.match), l.target
		}
	}
	if target == "" {
		return uri
	}
	return target
}

func (b *builder) collectLocs(kids []*node) {
	for _, l := range kids {
		if l.name != "location" || !l.block || len(l.args) == 0 {
			continue
		}
		t := locTarget{match: l.args[len(l.args)-1]}
		if len(l.args) > 1 {
			t.mod = l.args[0]
		}
		if urls, _ := b.backends(l.kids); len(urls) > 0 {
			t.target = urls[0]
		}
		b.locs = append(b.locs, t)
		b.collectLocs(l.kids)
	}
}

// redirects extrait les « return 30x » d'un bloc.
func redirects(kids []*node) []source.Middleware {
	var out []source.Middleware
	for _, k := range kids {
		if k.name != "return" || len(k.args) == 0 {
			continue
		}
		code, err := strconv.Atoi(k.args[0])
		if err != nil || (code != 301 && code != 302 && code != 303 && code != 307 && code != 308) {
			continue
		}
		cfg := map[string]any{"code": code}
		if len(k.args) > 1 {
			cfg["target"] = k.args[1]
		}
		j, _ := json.Marshal(cfg)
		out = append(out, source.Middleware{Name: "return", Type: "return", Kind: source.Redirect, Config: j})
	}
	return out
}
