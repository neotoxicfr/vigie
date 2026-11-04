// Package policy déduit, sans rien mesurer, ce qu'un inconnu obtient sur chaque
// route d'après sa chaîne de middlewares, et compare les chaînes à des modèles.
package policy

import (
	"fmt"
	"net/netip"
	"path"
	"slices"
	"strings"

	"github.com/neotoxicfr/vigie/internal/authprov"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/netinfo"
	"github.com/neotoxicfr/vigie/internal/source"
)

type Options struct {
	Templates      map[string][]string // modèle → middlewares attendus (nom court)
	RouteTemplates map[string]string   // motif path.Match de nom de route → modèle
	Public         []string            // motifs path.Match d'hôtes publics voulus
	Auth           authprov.Provider
	Egress         []netip.Addr // IP de sortie de vigie
	// CDNNotes : hôte → règles lues chez le CDN (géo, robots…) ; remplace « règles du
	// CDN non lues » dans la déduction.
	CDNNotes map[string]string
}

// Niveaux d'exposition, du plus ouvert au plus fermé.
const (
	Public       = "public"
	PublicViaCDN = "public-via-cdn"
	Auth         = "auth"
	Blocked      = "bloqué"
)

var rank = map[string]int{Public: 0, PublicViaCDN: 1, Auth: 2, Blocked: 3}

// methods : méthodes rejouées auprès du fournisseur d'authentification.
var methods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

var openness = map[string]int{authprov.Bypass: 0, authprov.OneFactor: 1, authprov.TwoFactor: 1, authprov.Deny: 2}

// Candidats « inconnus » : adresses de documentation, jamais routées.
var unknownCandidates = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("198.51.100.1"),
	netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("192.0.2.254"),
	netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("2001:db8:ffff::1"),
}

// unknownIP choisit une adresse de documentation absente de toutes les plages
// déclarées (listes blanches de la route, réseaux du fournisseur, sorties).
func unknownIP(r source.Route, o Options) netip.Addr {
	var declared []netip.Prefix
	for _, m := range r.Middlewares {
		if m.Kind == source.IPAllow {
			declared = append(declared, m.AllowFrom...)
		}
	}
	if n, ok := o.Auth.(authprov.Networker); ok {
		declared = append(declared, n.Networks()...)
	}
	for _, e := range o.Egress {
		declared = append(declared, netip.PrefixFrom(e, e.BitLen()))
	}
	// 0.0.0.0/0 et ::/0 couvrent tout le monde : ils ne déclarent personne.
	declared = slices.DeleteFunc(declared, func(p netip.Prefix) bool { return p.Bits() == 0 })
	for _, c := range unknownCandidates {
		if !slices.ContainsFunc(declared, func(p netip.Prefix) bool { return p.Contains(c) }) {
			return c
		}
	}
	return unknownCandidates[0]
}

func paths(r source.Route) []string {
	if len(r.Paths) == 0 {
		return []string{"/"}
	}
	return r.Paths
}

// exposure suit la chaîne dans l'ordre : le premier middleware qui arrête
// l'inconnu dit ce qu'il voit.
func exposure(r source.Route, host string, ip netip.Addr, o Options) (string, string) {
	via := ""
	var notes []string
	for _, m := range r.Middlewares {
		switch m.Kind {
		case source.IPAllow:
			if slices.ContainsFunc(m.AllowFrom, func(p netip.Prefix) bool { return p.Contains(ip) }) {
				notes = append(notes, fmt.Sprintf("liste blanche %s ouverte à tous", m.Name))
				continue
			}
			cdn := ""
			for _, p := range m.AllowFrom {
				if name, ok := netinfo.CDNOverlap(p); ok {
					cdn = name
					break
				}
			}
			if cdn == "" && m.OrAuth && slices.ContainsFunc(r.Middlewares, func(x source.Middleware) bool {
				return x.Kind == source.BasicAuth || x.Kind == source.ForwardAuth
			}) {
				// satisfy any : refusé par l'adresse, l'inconnu tente l'authentification.
				notes = append(notes, fmt.Sprintf("liste blanche %s contournable par authentification (satisfy any)", m.Name))
				continue
			}
			if cdn == "" {
				return Blocked, fmt.Sprintf("liste blanche %s : inconnu refusé", m.Name)
			}
			via = cdn
			if cn := o.CDNNotes[strings.ToLower(host)]; cn != "" {
				notes = append(notes, fmt.Sprintf("liste blanche %s : plages %s, filtrées en amont par %s", m.Name, cdn, cn))
			} else {
				notes = append(notes, fmt.Sprintf("liste blanche %s : plages %s, tout visiteur de ce CDN passe (règles du CDN non lues)", m.Name, cdn))
			}
		case source.BasicAuth:
			return Auth, joined(notes, fmt.Sprintf("basic-auth %s", m.Name))
		case source.ForwardAuth:
			if o.Auth == nil {
				return Auth, joined(notes, fmt.Sprintf("forward-auth %s : règles non lues", m.Name))
			}
			// Plusieurs chemins et méthodes : le plus ouvert l'emporte (un
			// bypass limité à POST, pour un webhook, ouvre la route).
			var d authprov.Decision
			method := ""
			for _, p := range paths(r) {
				for _, mt := range methods {
					if dd := o.Auth.Decide(host, p, mt, ip); method == "" || openness[dd.Policy] < openness[d.Policy] {
						d, method = dd, mt
					}
				}
			}
			why := fmt.Sprintf("%s via %s : %s en %s, %s", o.Auth.Name(), m.Name, d.Policy, method, d.Reason)
			switch d.Policy {
			case authprov.Bypass:
				notes = append(notes, why)
			case authprov.Deny:
				return Blocked, why
			default:
				return Auth, joined(notes, why)
			}
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "aucun contrôle d'accès dans la chaîne")
	}
	if via != "" {
		return PublicViaCDN, strings.Join(notes, " ; ")
	}
	return Public, strings.Join(notes, " ; ")
}

// joined : notes accumulées puis la raison finale.
func joined(notes []string, why string) string {
	return strings.Join(append(slices.Clip(notes), why), " ; ")
}

// Exposure dit ce qu'un inconnu voit de la route (déduit, jamais mesuré) :
// le niveau le plus ouvert parmi ses hôtes.
func Exposure(r source.Route, o Options) (level, reason string) {
	ip := unknownIP(r, o)
	hosts := r.Hosts
	if len(hosts) == 0 {
		hosts = []string{""}
	}
	for _, h := range hosts {
		l, why := exposure(r, h, ip, o)
		if level == "" || rank[l] < rank[level] {
			level, reason = l, why
			if h != "" && len(hosts) > 1 {
				reason = h + " : " + why
			}
		}
	}
	return level, reason
}

// Privileged : une IP de sortie de vigie passe une liste blanche de la route,
// ou obtient bypass du fournisseur alors qu'un inconnu ne l'obtient pas.
func Privileged(r source.Route, o Options) (bool, string) {
	for _, e := range o.Egress {
		for _, m := range r.Middlewares {
			if m.Kind == source.IPAllow && slices.ContainsFunc(m.AllowFrom, func(p netip.Prefix) bool { return p.Contains(e) }) {
				return true, fmt.Sprintf("%s passe la liste blanche %s", e, m.Name)
			}
		}
	}
	if o.Auth == nil || !slices.ContainsFunc(r.Middlewares, func(m source.Middleware) bool { return m.Kind == source.ForwardAuth }) {
		return false, ""
	}
	unknown := unknownIP(r, o)
	for _, h := range r.Hosts {
		for _, p := range paths(r) {
			for _, mt := range methods {
				if o.Auth.Decide(h, p, mt, unknown).Policy == authprov.Bypass {
					continue
				}
				for _, e := range o.Egress {
					if d := o.Auth.Decide(h, p, mt, e); d.Policy == authprov.Bypass {
						return true, fmt.Sprintf("%s obtient bypass de %s sur %s en %s (%s)", e, o.Auth.Name(), h, mt, d.Reason)
					}
				}
			}
		}
	}
	return false, ""
}

func short(name string) string {
	n, _, _ := strings.Cut(name, "@")
	return n
}

func target(r source.Route, host string) string {
	if len(r.Paths) == 1 && r.Paths[0] != "/" && r.Paths[0] != "" {
		return host + r.Paths[0]
	}
	return host
}

// privatePrefixes : plages non routées sur Internet, une liste blanche large
// dedans n'ouvre rien à l'extérieur.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

func wide(p netip.Prefix) bool {
	if p.Bits() == 0 {
		return true
	}
	if slices.ContainsFunc(privatePrefixes, func(q netip.Prefix) bool { return q.Bits() <= p.Bits() && q.Contains(p.Addr()) }) {
		return false
	}
	if p.Addr().Is4() {
		return p.Bits() <= 8
	}
	return p.Bits() <= 16
}

func matchAny(patterns []string, s string) bool {
	return slices.ContainsFunc(patterns, func(p string) bool { ok, _ := path.Match(p, s); return ok })
}

// templateFor : premier motif (ordre alphabétique) qui couvre le nom de la
// route, complet ou sans @provider.
func templateFor(name string, o Options) (string, bool) {
	keys := make([]string, 0, len(o.RouteTemplates))
	for k := range o.RouteTemplates {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		if matchAny([]string{k}, name) || matchAny([]string{k}, short(name)) {
			return o.RouteTemplates[k], true
		}
	}
	return "", false
}

// Analyze produit les constats de configuration et d'exposition des routes.
func Analyze(routes []source.Route, o Options) []check.Finding {
	var out []check.Finding
	add := func(f check.Finding) { out = append(out, f) }
	seen := map[string][]string{} // hôte+chemin → routes
	for _, r := range routes {
		hosts := r.Hosts
		if len(hosts) == 0 {
			hosts = []string{r.Name}
		}
		ip := unknownIP(r, o)
		var missing []string
		var tplProblem string
		if tpl, ok := templateFor(r.Name, o); ok {
			want, ok := o.Templates[tpl]
			if !ok {
				tplProblem = fmt.Sprintf("modèle %q inconnu", tpl)
			}
			have := map[string]bool{}
			for _, d := range r.Declared {
				have[short(d)] = true
			}
			for _, m := range r.Middlewares {
				have[short(m.Name)] = true
			}
			for _, w := range want {
				if !have[short(w)] {
					missing = append(missing, short(w))
				}
			}
			if len(missing) > 0 {
				missing = append([]string{"modèle " + tpl + " :"}, missing...)
			}
		}
		var wides []string
		for _, m := range r.Middlewares {
			if m.Kind != source.IPAllow {
				continue
			}
			for _, p := range m.AllowFrom {
				if wide(p) {
					wides = append(wides, m.Name+" "+p.String())
				}
			}
		}
		for _, h := range hosts {
			t := target(r, h)
			problems := slices.Clone(r.Problems)
			if tplProblem != "" {
				problems = append(problems, tplProblem)
			}
			if len(problems) > 0 {
				add(check.Finding{Check: "chain.problem", Target: t, Vantage: "config", Severity: check.Low,
					Title: "Chaîne de middlewares incohérente", Evidence: r.Name + " : " + strings.Join(problems, " ; ")})
			}
			if len(missing) > 0 {
				add(check.Finding{Check: "chain.template.missing", Target: t, Vantage: "config", Severity: check.Medium,
					Title: "Middleware attendu absent", Evidence: r.Name + " : " + strings.Join(missing, " ")})
			}
			if len(wides) > 0 {
				add(check.Finding{Check: "chain.allowlist.wide", Target: t, Vantage: "config", Severity: check.Medium,
					Title: "Liste blanche trop large", Evidence: r.Name + " : " + strings.Join(wides, ", ")})
			}
			if len(r.Hosts) == 0 {
				continue
			}
			level, why := exposure(r, h, ip, o)
			add(check.Finding{Check: "chain.exposure", Target: t, Vantage: "inconnu", Severity: check.Info,
				Title: "Exposition déduite : " + level, Evidence: r.Name + " : " + why})
			if (level == Public || level == PublicViaCDN) && !matchAny(o.Public, strings.ToLower(h)) {
				add(check.Finding{Check: "chain.exposed", Target: t, Vantage: "inconnu", Severity: check.High,
					Title: "Route ouverte à tous sans contrôle d'accès", Evidence: r.Name + " : " + why})
			}
			for _, p := range paths(r) {
				k := strings.ToLower(h) + strings.TrimSuffix(p, "/")
				if !slices.Contains(seen[k], r.Name) {
					seen[k] = append(seen[k], r.Name)
				}
			}
		}
	}
	keys := make([]string, 0, len(seen))
	for k, names := range seen {
		if len(names) > 1 {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	for _, k := range keys {
		add(check.Finding{Check: "chain.duplicate-host", Target: k, Vantage: "config", Severity: check.Info,
			Title: "Hôte servi par plusieurs routes", Evidence: strings.Join(seen[k], ", ")})
	}
	return merge(out)
}

// merge fusionne les constats de même clé (plusieurs routes sur un hôte) :
// preuves jointes, sévérité la plus haute, 300 caractères au plus.
func merge(in []check.Finding) []check.Finding {
	var out []check.Finding
	idx := map[string]int{}
	for _, f := range in {
		if i, ok := idx[f.Key()]; ok {
			g := &out[i]
			g.Evidence += " | " + f.Evidence
			g.Severity = max(g.Severity, f.Severity)
			continue
		}
		idx[f.Key()] = len(out)
		out = append(out, f)
	}
	for i := range out {
		if r := []rune(out[i].Evidence); len(r) > 300 {
			out[i].Evidence = string(r[:299]) + "…"
		}
	}
	return out
}
