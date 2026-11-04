// Package traefik découvre les routes HTTP d'une instance Traefik v2/v3 par son
// API, en lecture seule.
package traefik

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/source"
)

type Traefik struct {
	name, base           string
	username, passwdFile string
	client               *http.Client
}

func New(name, baseURL, username, passwordFile string) *Traefik {
	return &Traefik{name, strings.TrimRight(baseURL, "/"), username, passwordFile,
		&http.Client{Timeout: 15 * time.Second}}
}

func (t *Traefik) Name() string { return "traefik/" + t.name }

type router struct {
	Name        string          `json:"name"`
	Provider    string          `json:"provider"`
	Status      string          `json:"status"`
	Rule        string          `json:"rule"`
	EntryPoints []string        `json:"entryPoints"`
	Middlewares []string        `json:"middlewares"`
	Service     string          `json:"service"`
	TLS         json.RawMessage `json:"tls"`
}

type middleware struct {
	Name     string                     `json:"name"`
	Provider string                     `json:"provider"`
	Type     string                     `json:"type"`
	Raw      map[string]json.RawMessage `json:"-"`
}

type service struct {
	Name         string `json:"name"`
	LoadBalancer *struct {
		Servers []struct {
			URL string `json:"url"`
		} `json:"servers"`
	} `json:"loadBalancer"`
}

type entryPoint struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	HTTP    struct {
		Middlewares []string `json:"middlewares"`
	} `json:"http"`
}

func (t *Traefik) Discover(ctx context.Context) ([]source.Route, error) {
	var (
		routers []router
		mwsRaw  []json.RawMessage
		svcs    []service
		eps     []entryPoint
	)
	for p, dst := range map[string]any{"/api/http/routers": &routers, "/api/http/middlewares": &mwsRaw,
		"/api/http/services": &svcs, "/api/entrypoints": &eps} {
		if err := t.getAll(ctx, p, dst); err != nil {
			return nil, fmt.Errorf("%s : %w", t.Name(), err)
		}
	}
	mws := map[string]middleware{}
	for _, raw := range mwsRaw {
		var m middleware
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		json.Unmarshal(raw, &m.Raw)
		mws[m.Name] = m
	}
	backends := map[string][]string{}
	for _, s := range svcs {
		if s.LoadBalancer != nil {
			for _, srv := range s.LoadBalancer.Servers {
				backends[s.Name] = append(backends[s.Name], srv.URL)
			}
		}
	}
	epByName := map[string]entryPoint{}
	for _, e := range eps {
		epByName[e.Name] = e
	}

	var out []source.Route
	for _, r := range routers {
		if r.Provider == "internal" || r.Status == "disabled" {
			continue
		}
		rt := source.Route{Source: t.Name(), Name: r.Name, Rule: r.Rule, TLS: len(r.TLS) > 0 && string(r.TLS) != "null",
			Hosts: ruleValues(hostRe, r.Rule), Paths: ruleValues(pathRe, r.Rule)}
		if len(rt.Hosts) == 0 {
			rt.Problems = append(rt.Problems, "aucun Host() littéral dans la règle : hôtes non scannables")
		}
		// L'API v3 inclut déjà les middlewares d'entrypoint dans ceux du routeur ;
		// on ne les ajoute que s'ils manquent (v2).
		declared := []string{}
		seen := map[string]bool{}
		for _, ep := range r.EntryPoints {
			e, ok := epByName[ep]
			if !ok {
				rt.Problems = append(rt.Problems, "entrypoint "+ep+" introuvable")
				continue
			}
			if port := addrPort(e.Address); port > 0 {
				rt.Ports = append(rt.Ports, port)
			}
			for _, m := range e.HTTP.Middlewares {
				if q := qualify(m, r.Provider); !seen[q] && !contains(r.Middlewares, m, r.Provider) {
					seen[q] = true
					declared = append(declared, q)
				}
			}
		}
		for _, m := range r.Middlewares {
			if q := qualify(m, r.Provider); !seen[q] {
				seen[q] = true
				declared = append(declared, q)
			}
		}
		rt.Declared = declared
		for _, m := range declared {
			rt.Middlewares, rt.Problems = flatten(m, mws, rt.Middlewares, rt.Problems, map[string]bool{})
		}
		if r.Service != "" {
			rt.Backends = backends[qualify(r.Service, r.Provider)]
		}
		out = append(out, rt)
	}
	return out, nil
}

// flatten déroule une chaîne en ses middlewares, dans l'ordre, sans boucler.
func flatten(name string, mws map[string]middleware, acc []source.Middleware, probs []string, stack map[string]bool) ([]source.Middleware, []string) {
	if stack[name] {
		return acc, append(probs, "chaîne cyclique via "+name)
	}
	m, ok := mws[name]
	if !ok {
		return acc, append(probs, "middleware "+name+" introuvable")
	}
	if m.Type == "chain" {
		var c struct {
			Middlewares []string `json:"middlewares"`
		}
		json.Unmarshal(m.Raw["chain"], &c)
		stack[name] = true
		for _, sub := range c.Middlewares {
			acc, probs = flatten(qualify(sub, m.Provider), mws, acc, probs, stack)
		}
		delete(stack, name)
		return acc, probs
	}
	return append(acc, convert(m)), probs
}

func convert(m middleware) source.Middleware {
	out := source.Middleware{Name: m.Name, Type: m.Type, Kind: source.Other}
	// La config est sous une clé au nom du type (casse variable : ipAllowList, plugin…).
	for k, v := range m.Raw {
		switch k {
		case "name", "provider", "type", "status", "usedBy", "error":
		default:
			out.Config = v
		}
	}
	switch strings.ToLower(m.Type) {
	case "ipallowlist", "ipwhitelist":
		out.Kind = source.IPAllow
		var c struct {
			SourceRange []string `json:"sourceRange"`
		}
		json.Unmarshal(out.Config, &c)
		for _, s := range c.SourceRange {
			if p, err := parsePrefix(s); err == nil {
				out.AllowFrom = append(out.AllowFrom, p)
			}
		}
	case "forwardauth":
		out.Kind = source.ForwardAuth
		var c struct {
			Address string `json:"address"`
		}
		json.Unmarshal(out.Config, &c)
		out.AuthURL = c.Address
	case "basicauth", "digestauth":
		out.Kind = source.BasicAuth
	case "headers":
		out.Kind = source.Headers
	case "ratelimit", "inflightreq":
		out.Kind = source.RateLimit
	case "redirectscheme", "redirectregex":
		out.Kind = source.Redirect
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

// Valeurs littérales des matchers Host(...) et Path/PathPrefix(...) ; HostRegexp
// et PathRegexp sont ignorés (motifs, pas des cibles).
var (
	hostRe = regexp.MustCompile(`\bHost\(([^)]*)\)`)
	pathRe = regexp.MustCompile(`\bPath(?:Prefix)?\(([^)]*)\)`)
	argRe  = regexp.MustCompile("`([^`]*)`|\"([^\"]*)\"")
)

func ruleValues(re *regexp.Regexp, rule string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(rule, -1) {
		for _, a := range argRe.FindAllStringSubmatch(m[1], -1) {
			v := a[1] + a[2]
			if v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
	}
	return out
}

func qualify(name, provider string) string {
	if strings.Contains(name, "@") {
		return name
	}
	return name + "@" + provider
}

func contains(list []string, name, provider string) bool {
	q := qualify(name, provider)
	for _, l := range list {
		if qualify(l, provider) == q {
			return true
		}
	}
	return false
}

func addrPort(addr string) int {
	_, p, err := net.SplitHostPort(strings.SplitN(addr, "/", 2)[0]) // ":443/udp" possible
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(p)
	return n
}

const (
	maxBody  = 16 << 20
	maxPages = 100
)

// getAll lit toutes les pages d'un point de l'API (X-Next-Page vaut 1 sur la dernière).
func (t *Traefik) getAll(ctx context.Context, path string, dst any) error {
	var all []json.RawMessage
	total := 0
	for page := 1; ; {
		if page > maxPages {
			return fmt.Errorf("GET %s : plus de %d pages", redact(t.base+path), maxPages)
		}
		u := t.base + path + "?per_page=100&page=" + strconv.Itoa(page)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		if t.username != "" {
			pw, err := os.ReadFile(t.passwdFile)
			if err != nil {
				return err
			}
			req.SetBasicAuth(t.username, strings.TrimSpace(string(pw)))
		}
		resp, err := t.client.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("GET %s : %s", redact(u), resp.Status)
		}
		if len(body) > maxBody {
			return fmt.Errorf("GET %s : réponse > %d octets", redact(u), maxBody)
		}
		if total += len(body); total > maxBody {
			return fmt.Errorf("GET %s : réponses cumulées > %d octets", redact(t.base+path), maxBody)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(body, &items); err != nil {
			return fmt.Errorf("GET %s : %w", redact(u), err)
		}
		all = append(all, items...)
		next, _ := strconv.Atoi(resp.Header.Get("X-Next-Page"))
		if next <= page {
			break
		}
		page = next
	}
	b, _ := json.Marshal(all)
	return json.Unmarshal(b, dst)
}

func redact(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return "?"
	}
	return p.Redacted()
}
