// Package authelia lit la section access_control d'une configuration Authelia
// et rejoue sa décision pour un visiteur anonyme.
//
// Sémantique reprise du code d'Authelia (internal/authorization) :
//   - la première règle dont tous les critères correspondent l'emporte, sinon
//     default_policy (deny si vide) ;
//   - domain et domain_regex forment une seule liste (OU) ; « *.x » couvre les
//     sous-domaines de x mais pas x ; casse ignorée ; {user} et {group}
//     deviennent des expressions qui, pour un anonyme, correspondent sans
//     condition d'identité ;
//   - resources : expressions non ancrées sur le chemin nettoyé suivi de
//     « ?requête » ; query : OU de groupes de conditions en ET ;
//   - networks : CIDR, IP ou noms déclarés sous access_control.networks ;
//   - une règle à sujet (subject, ou groupe nommé User/Group dans une
//     expression) CORRESPOND à un anonyme : il reçoit sa politique ; avec deny,
//     Authelia lui demande de s'authentifier plutôt que de refuser.
//
// Seule access_control est décodée : le reste du fichier (secrets) n'est ni
// conservé ni journalisé.
package authelia

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/neotoxicfr/vigie/internal/authprov"
)

const maxSize = 1 << 20

type Authelia struct {
	def   string
	rules []rule
}

type rule struct {
	domains   []func(string) bool
	resources []*regexp.Regexp
	query     [][]queryCond
	methods   []string
	networks  []netip.Prefix
	subjects  bool
	policy    string
}

type queryCond struct {
	key, op, value string
	re             *regexp.Regexp
}

// list accepte une chaîne seule ou une liste, comme Authelia.
type list []string

func (l *list) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*l = list{n.Value}
		return nil
	}
	var s []string
	if err := n.Decode(&s); err != nil {
		return err
	}
	*l = s
	return nil
}

type rawRule struct {
	Domain      list      `yaml:"domain"`
	DomainRegex list      `yaml:"domain_regex"`
	Policy      string    `yaml:"policy"`
	Networks    list      `yaml:"networks"`
	Resources   list      `yaml:"resources"`
	Methods     list      `yaml:"methods"`
	Subject     yaml.Node `yaml:"subject"`
	Query       [][]struct {
		Key      string `yaml:"key"`
		Value    any    `yaml:"value"`
		Operator string `yaml:"operator"`
	} `yaml:"query"`
}

type rawConfig struct {
	AccessControl struct {
		DefaultPolicy string `yaml:"default_policy"`
		Networks      []struct {
			Name     string `yaml:"name"`
			Networks list   `yaml:"networks"`
		} `yaml:"networks"`
		Rules []rawRule `yaml:"rules"`
	} `yaml:"access_control"`
}

// Load lit configuration.yml (1 Mo au plus).
func Load(file string) (*Authelia, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("%s : plus de %d octets", file, maxSize)
	}
	return Parse(data)
}

// Parse interprète access_control d'une configuration déjà lue.
func Parse(data []byte) (*Authelia, error) {
	var raw rawConfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, errors.New("authelia : YAML illisible")
	}
	ac := raw.AccessControl
	a := &Authelia{def: ac.DefaultPolicy}
	if a.def == "" {
		a.def = authprov.Deny
	}
	if !validPolicy(a.def) {
		return nil, fmt.Errorf("authelia : default_policy %q inconnue", a.def)
	}
	named := map[string][]netip.Prefix{}
	for _, n := range ac.Networks {
		for _, s := range n.Networks {
			p, err := parseNet(s)
			if err != nil {
				return nil, fmt.Errorf("authelia : réseau %q : %w", n.Name, err)
			}
			named[n.Name] = append(named[n.Name], p)
		}
	}
	if len(ac.Rules) == 0 && a.def != authprov.OneFactor && a.def != authprov.TwoFactor {
		return nil, fmt.Errorf("authelia : aucune règle avec default_policy %s (refusé par Authelia)", a.def)
	}
	for i, rr := range ac.Rules {
		r, err := compile(rr, named)
		if err != nil {
			return nil, fmt.Errorf("authelia : règle n°%d : %w", i+1, err)
		}
		a.rules = append(a.rules, r)
	}
	return a, nil
}

func validPolicy(p string) bool {
	return p == authprov.Bypass || p == authprov.OneFactor || p == authprov.TwoFactor || p == authprov.Deny
}

func parseNet(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%q n'est ni une IP ni un CIDR", s)
	}
	ip = ip.Unmap()
	return netip.PrefixFrom(ip, ip.BitLen()), nil
}

func identityGroups(re *regexp.Regexp) bool {
	return slices.Contains(re.SubexpNames(), "User") || slices.Contains(re.SubexpNames(), "Group")
}

func compile(rr rawRule, named map[string][]netip.Prefix) (rule, error) {
	r := rule{policy: rr.Policy}
	if !validPolicy(r.policy) {
		return r, fmt.Errorf("politique %q inconnue", r.policy)
	}
	if len(rr.Domain)+len(rr.DomainRegex) == 0 {
		return r, errors.New("ni domain ni domain_regex")
	}
	for _, d := range rr.Domain {
		d = strings.ToLower(d)
		switch {
		case strings.HasPrefix(d, "*."):
			suffix := d[1:]
			r.domains = append(r.domains, func(h string) bool { return strings.HasSuffix(h, suffix) })
		case strings.HasPrefix(d, "{user}"):
			re := regexp.MustCompile(`(?i)^(?P<User>[a-z0-9-]+(?:\.[a-z0-9-]+)*)` + regexp.QuoteMeta(d[len("{user}"):]) + `$`)
			r.domains = append(r.domains, re.MatchString)
			r.subjects = true
		case strings.HasPrefix(d, "{group}"):
			re := regexp.MustCompile(`(?i)^(?P<Group>[a-z0-9-]+)` + regexp.QuoteMeta(d[len("{group}"):]) + `$`)
			r.domains = append(r.domains, re.MatchString)
			r.subjects = true
		default:
			r.domains = append(r.domains, func(h string) bool { return h == d })
		}
	}
	for _, s := range rr.DomainRegex {
		re, err := regexp.Compile(s)
		if err != nil {
			return r, fmt.Errorf("domain_regex invalide : %w", err)
		}
		r.domains = append(r.domains, re.MatchString)
		r.subjects = r.subjects || identityGroups(re)
	}
	for _, s := range rr.Resources {
		re, err := regexp.Compile(s)
		if err != nil {
			return r, fmt.Errorf("resources invalide : %w", err)
		}
		r.resources = append(r.resources, re)
		r.subjects = r.subjects || identityGroups(re)
	}
	for _, m := range rr.Methods {
		r.methods = append(r.methods, strings.ToUpper(m))
	}
	for _, n := range rr.Networks {
		if ps, ok := named[n]; ok {
			r.networks = append(r.networks, ps...)
			continue
		}
		p, err := parseNet(n)
		if err != nil {
			return r, fmt.Errorf("networks : %q n'est ni un nom déclaré ni un CIDR", n)
		}
		r.networks = append(r.networks, p)
	}
	if !rr.Subject.IsZero() && !(rr.Subject.Kind == yaml.ScalarNode && rr.Subject.Value == "") &&
		!(rr.Subject.Kind == yaml.SequenceNode && len(rr.Subject.Content) == 0) {
		r.subjects = true
	}
	if r.subjects && r.policy == authprov.Bypass {
		return r, errors.New("bypass avec sujet (refusé par Authelia)")
	}
	for _, group := range rr.Query {
		var conds []queryCond
		for _, q := range group {
			c := queryCond{key: q.Key, op: strings.ToLower(q.Operator)}
			if q.Value != nil {
				c.value = fmt.Sprint(q.Value)
			}
			if c.op == "" {
				if c.value == "" {
					c.op = "present"
				} else {
					c.op = "equal"
				}
			}
			switch c.op {
			case "present", "absent", "equal", "not equal":
			case "pattern", "not pattern":
				re, err := regexp.Compile(c.value)
				if err != nil {
					return r, fmt.Errorf("query invalide : %w", err)
				}
				c.re = re
			default:
				return r, fmt.Errorf("opérateur de query %q inconnu", q.Operator)
			}
			conds = append(conds, c)
		}
		r.query = append(r.query, conds)
	}
	return r, nil
}

func (a *Authelia) Name() string { return "authelia" }

// Decide rejoue access_control pour un anonyme venant de ip. path peut
// contenir « ?requête ».
func (a *Authelia) Decide(host, reqPath, method string, ip netip.Addr) authprov.Decision {
	if reqPath == "" || reqPath[0] != '/' {
		reqPath = "/" + reqPath
	}
	u, err := url.ParseRequestURI("https://" + host + reqPath)
	if err != nil {
		return authprov.Decision{Policy: a.def, Rule: -1, Reason: "URL illisible : politique par défaut"}
	}
	domain := strings.ToLower(u.Hostname())
	full := cleanPath(u)
	method = strings.ToUpper(method)
	ip = ip.Unmap()
	for i, r := range a.rules {
		if !r.match(domain, full, method, u.Query(), ip) {
			continue
		}
		d := authprov.Decision{Policy: r.policy, Rule: i, Reason: fmt.Sprintf("règle n°%d", i+1)}
		if r.subjects {
			if r.policy == authprov.Deny {
				// Authelia (authz : isAuthzResult) répond 401 et renvoie l'anonyme
				// au portail : pour lui, c'est une authentification, pas un refus.
				d.Policy = authprov.OneFactor
				d.Reason += " (deny à sujet : l'anonyme voit le portail, refus après connexion)"
			} else {
				d.Reason += " (à sujet : seuls les comptes visés passent)"
			}
		}
		return d
	}
	return authprov.Decision{Policy: a.def, Rule: -1, Reason: "aucune règle : politique par défaut"}
}

func (r rule) match(domain, full, method string, q url.Values, ip netip.Addr) bool {
	if !slices.ContainsFunc(r.domains, func(m func(string) bool) bool { return m(domain) }) {
		return false
	}
	if len(r.resources) > 0 && !slices.ContainsFunc(r.resources, func(re *regexp.Regexp) bool { return re.MatchString(full) }) {
		return false
	}
	if len(r.query) > 0 && !slices.ContainsFunc(r.query, func(g []queryCond) bool {
		for _, c := range g {
			if !c.match(q) {
				return false
			}
		}
		return true
	}) {
		return false
	}
	if len(r.methods) > 0 && !slices.Contains(r.methods, method) {
		return false
	}
	if len(r.networks) > 0 && !slices.ContainsFunc(r.networks, func(p netip.Prefix) bool { return p.Contains(ip) }) {
		return false
	}
	return true
}

func (c queryCond) match(q url.Values) bool {
	switch c.op {
	case "present":
		return q.Has(c.key)
	case "absent":
		return !q.Has(c.key)
	case "equal":
		return q.Get(c.key) == c.value
	case "not equal":
		return q.Get(c.key) != c.value
	case "pattern":
		return c.re.MatchString(q.Get(c.key))
	default: // not pattern
		return !c.re.MatchString(q.Get(c.key))
	}
}

// cleanPath reprend utils.URLPathFullClean d'Authelia.
func cleanPath(u *url.URL) string {
	p, q := u.Path, u.RawQuery
	slash := len(p) > 1 && p[len(p)-1] == '/'
	switch {
	case len(p) == 1 && q == "":
		return p
	case len(p) == 1:
		return path.Clean(p) + "?" + q
	case q != "" && slash:
		return path.Clean(p) + "/?" + q
	case q != "":
		return path.Clean(p) + "?" + q
	case slash:
		return path.Clean(p) + "/"
	default:
		return path.Clean(p)
	}
}

// Networks liste les réseaux cités par les règles.
func (a *Authelia) Networks() []netip.Prefix {
	var out []netip.Prefix
	for _, r := range a.rules {
		out = append(out, r.networks...)
	}
	return out
}
