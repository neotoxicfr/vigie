package policy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/authprov"
	"github.com/neotoxicfr/vigie/internal/authprov/authelia"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/source"
)

func pfx(ss ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

func allow(name string, ss ...string) source.Middleware {
	return source.Middleware{Name: name, Kind: source.IPAllow, AllowFrom: pfx(ss...)}
}

var (
	fwd    = source.Middleware{Name: "authelia@file", Kind: source.ForwardAuth}
	basic  = source.Middleware{Name: "basic@file", Kind: source.BasicAuth}
	lan    = allow("lan@file", "192.168.0.0/16")
	lanAny = source.Middleware{Name: "allow/deny", Kind: source.IPAllow, AllowFrom: pfx("192.168.0.0/16"), OrAuth: true}
	cf     = allow("cf@file", "173.245.48.0/20", "2400:cb00::/32")
)

func provider(t *testing.T, y string) authprov.Provider {
	t.Helper()
	a, err := authelia.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

const autheliaYAML = `
access_control:
  default_policy: one_factor
  rules:
    - domain: open.example.com
      policy: bypass
    - domain: shut.example.com
      policy: deny
    - domain: lan.example.com
      networks: [192.168.0.0/16]
      policy: bypass
    - domain: doc.example.com
      networks: [192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24]
      policy: bypass
    - domain: api.example.com
      resources: ['^/public']
      policy: bypass
    - domain: hook.example.com
      methods: [POST]
      policy: bypass
    - domain: hook.example.com
      policy: deny
    - domain: team.example.com
      subject: 'group:admins'
      policy: deny
`

func TestExposure(t *testing.T) {
	auth := provider(t, autheliaYAML)
	for _, c := range []struct {
		name   string
		host   string
		paths  []string
		chain  []source.Middleware
		auth   authprov.Provider
		level  string
		reason string
	}{
		{"nue", "a.example.com", nil, nil, nil, Public, "aucun contrôle"},
		{"lan seul", "a.example.com", nil, []source.Middleware{lan}, nil, Blocked, "lan@file"},
		{"cdn", "a.example.com", nil, []source.Middleware{cf}, nil, PublicViaCDN, "cloudflare"},
		{"cdn v6 seul", "a.example.com", nil, []source.Middleware{allow("cf6", "2606:4700::/32")}, nil, PublicViaCDN, "non lues"},
		{"tous", "a.example.com", nil, []source.Middleware{allow("all", "0.0.0.0/0")}, nil, Public, "ouverte à tous"},
		{"fwd sans fournisseur", "a.example.com", nil, []source.Middleware{fwd}, nil, Auth, "règles non lues"},
		{"basic", "a.example.com", nil, []source.Middleware{basic}, nil, Auth, "basic"},
		{"ordre lan puis basic", "a.example.com", nil, []source.Middleware{lan, basic}, nil, Blocked, ""},
		{"ordre basic puis lan", "a.example.com", nil, []source.Middleware{basic, lan}, nil, Auth, ""},
		{"cdn + bypass", "open.example.com", nil, []source.Middleware{cf, fwd}, auth, PublicViaCDN, "bypass"},
		{"cdn + 1 facteur", "a.example.com", nil, []source.Middleware{cf, fwd}, auth, Auth, "one_factor"},
		{"deny", "shut.example.com", nil, []source.Middleware{fwd}, auth, Blocked, "deny"},
		{"réseau lan : inconnu exclu", "lan.example.com", nil, []source.Middleware{fwd}, auth, Auth, ""},
		{"IP inconnue hors réseaux déclarés", "doc.example.com", nil, []source.Middleware{fwd}, auth, Auth, ""},
		{"chemin le plus ouvert", "api.example.com", []string{"/admin", "/public"}, []source.Middleware{fwd}, auth, Public, "bypass"},
		{"chemin fermé", "api.example.com", []string{"/admin"}, []source.Middleware{fwd}, auth, Auth, ""},
		{"bypass sur POST seul", "hook.example.com", nil, []source.Middleware{fwd}, auth, Public, "bypass en POST"},
		{"deny à sujet : portail", "team.example.com", nil, []source.Middleware{fwd}, auth, Auth, "portail"},
		{"satisfy any + basic", "a.example.com", nil, []source.Middleware{lanAny, basic}, nil, Auth, "satisfy any"},
		{"satisfy any + bypass", "open.example.com", nil, []source.Middleware{lanAny, fwd}, auth, Public, "bypass"},
		{"satisfy any sans auth", "a.example.com", nil, []source.Middleware{lanAny}, nil, Blocked, ""},
	} {
		r := source.Route{Name: c.name, Hosts: []string{c.host}, Paths: c.paths, Middlewares: c.chain}
		level, why := Exposure(r, Options{Auth: c.auth})
		if level != c.level || !strings.Contains(why, c.reason) {
			t.Errorf("%s : %s (%s) ; attendu %s (%q)", c.name, level, why, c.level, c.reason)
		}
	}
	// Plusieurs hôtes : le plus ouvert.
	r := source.Route{Hosts: []string{"shut.example.com", "open.example.com"}, Middlewares: []source.Middleware{fwd}}
	if l, why := Exposure(r, Options{Auth: auth}); l != Public || !strings.HasPrefix(why, "open.example.com") {
		t.Errorf("multi-hôtes : %s %s", l, why)
	}
}

func TestUnknownIP(t *testing.T) {
	r := source.Route{Middlewares: []source.Middleware{allow("x", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")}}
	if ip := unknownIP(r, Options{}); !ip.Is6() {
		t.Errorf("toutes les v4 de doc déclarées : %s", ip)
	}
	r = source.Route{Middlewares: []source.Middleware{allow("x", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")}}
	if ip := unknownIP(r, Options{}); !ip.IsValid() {
		t.Error("repli attendu")
	}
	if ip := unknownIP(source.Route{}, Options{Egress: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}); ip.String() == "192.0.2.1" {
		t.Error("l'IP de sortie ne doit pas servir d'inconnu")
	}
}

func TestPrivileged(t *testing.T) {
	auth := provider(t, autheliaYAML)
	lanIP := []netip.Addr{netip.MustParseAddr("192.168.1.10")}
	pubIP := []netip.Addr{netip.MustParseAddr("203.0.113.50")}
	for _, c := range []struct {
		name   string
		host   string
		chain  []source.Middleware
		egress []netip.Addr
		want   bool
	}{
		{"allowlist", "a.example.com", []source.Middleware{lan}, lanIP, true},
		{"hors allowlist", "a.example.com", []source.Middleware{lan}, pubIP, false},
		{"bypass réservé", "lan.example.com", []source.Middleware{fwd}, lanIP, true},
		{"bypass pour tous", "open.example.com", []source.Middleware{fwd}, lanIP, false},
		{"pas de bypass", "a.example.com", []source.Middleware{fwd}, lanIP, false},
		{"IPv6", "a.example.com", []source.Middleware{allow("v6", "2001:db8:1::/48")}, []netip.Addr{netip.MustParseAddr("2001:db8:1::9")}, true},
		{"sans sortie", "lan.example.com", []source.Middleware{fwd}, nil, false},
	} {
		r := source.Route{Hosts: []string{c.host}, Middlewares: c.chain}
		got, why := Privileged(r, Options{Auth: auth, Egress: c.egress})
		if got != c.want || got == (why == "") {
			t.Errorf("%s : %v (%s)", c.name, got, why)
		}
	}
}

func find(fs []check.Finding, id, target string) *check.Finding {
	for i := range fs {
		if fs[i].Check == id && fs[i].Target == target {
			return &fs[i]
		}
	}
	return nil
}

func TestAnalyze(t *testing.T) {
	routes := []source.Route{
		{Name: "app@docker", Hosts: []string{"app.example.com"}, Declared: []string{"secure@file"},
			Middlewares: []source.Middleware{lan, {Name: "headers@file", Kind: source.Headers}}, Problems: []string{"middleware x absent"}},
		{Name: "site@docker", Hosts: []string{"www.example.com"}},
		{Name: "blog@docker", Hosts: []string{"blog.example.com"}, Middlewares: []source.Middleware{cf}},
		{Name: "wide@file", Hosts: []string{"w.example.com"}, Middlewares: []source.Middleware{
			allow("w", "8.0.0.0/8", "45.0.0.0/12", "10.0.0.0/8", "2001::/16", "2001:db8::/32", "fd00::/8")}},
		{Name: "all@file", Hosts: []string{"all.example.com"}, Middlewares: []source.Middleware{allow("all", "0.0.0.0/0")}},
		{Name: "bis@docker", Hosts: []string{"WWW.example.com"}},
		{Name: "odd@docker", Hosts: []string{"odd.example.com"}},
	}
	o := Options{
		Templates:      map[string][]string{"prive": {"lan@file", "headers", "secure", "auth"}},
		RouteTemplates: map[string]string{"app": "prive", "odd*": "absent"},
		Public:         []string{"www.example.com", "*.public.example.com"},
	}
	fs := Analyze(routes, o)
	expect := func(id, target string, sev check.Severity, ev string) {
		t.Helper()
		f := find(fs, id, target)
		if f == nil {
			t.Errorf("%s %s absent", id, target)
			return
		}
		if f.Severity != sev || !strings.Contains(f.Evidence, ev) {
			t.Errorf("%s %s : %v %q", id, target, f.Severity, f.Evidence)
		}
		if len([]rune(f.Evidence)) > 300 {
			t.Errorf("%s : preuve trop longue", id)
		}
	}
	none := func(id, target string) {
		t.Helper()
		if find(fs, id, target) != nil {
			t.Errorf("%s %s inattendu", id, target)
		}
	}
	expect("chain.problem", "app.example.com", check.Low, "middleware x absent")
	expect("chain.template.missing", "app.example.com", check.Medium, "auth")
	if f := find(fs, "chain.template.missing", "app.example.com"); f != nil && strings.Contains(f.Evidence, "secure") {
		t.Errorf("secure est déclaré : %q", f.Evidence)
	}
	expect("chain.problem", "odd.example.com", check.Low, "inconnu")
	expect("chain.exposure", "app.example.com", check.Info, "lan@file")
	none("chain.exposed", "app.example.com")
	none("chain.exposed", "www.example.com") // public voulu
	expect("chain.exposure", "www.example.com", check.Info, "aucun contrôle")
	expect("chain.exposed", "blog.example.com", check.High, "cloudflare")
	expect("chain.exposed", "odd.example.com", check.High, "")
	expect("chain.allowlist.wide", "w.example.com", check.Medium, "8.0.0.0/8")
	if f := find(fs, "chain.allowlist.wide", "w.example.com"); f != nil &&
		(strings.Contains(f.Evidence, "10.0.0.0/8") || strings.Contains(f.Evidence, "45.0.0.0/12") || !strings.Contains(f.Evidence, "2001::/16") ||
			strings.Contains(f.Evidence, "2001:db8::/32") || strings.Contains(f.Evidence, "fd00::/8")) {
		t.Errorf("plages larges : %q", f.Evidence)
	}
	expect("chain.allowlist.wide", "all.example.com", check.Medium, "0.0.0.0/0")
	expect("chain.duplicate-host", "www.example.com", check.Info, "site@docker, bis@docker")
	none("chain.allowlist.wide", "app.example.com")
	for _, f := range fs {
		want := "config"
		if f.Check == "chain.exposure" || f.Check == "chain.exposed" {
			want = "inconnu"
		}
		if f.Vantage != want {
			t.Errorf("%s : vantage %s", f.Check, f.Vantage)
		}
	}
	keys := map[string]bool{}
	for _, f := range fs {
		if keys[f.Key()] {
			t.Errorf("clé en double : %s %s", f.Check, f.Target)
		}
		keys[f.Key()] = true
	}
}

func TestMerge(t *testing.T) {
	long := strings.Repeat("é", 200)
	fs := merge([]check.Finding{
		{Check: "c", Target: "t", Severity: check.Info, Evidence: long},
		{Check: "c", Target: "t", Severity: check.High, Evidence: long},
	})
	if len(fs) != 1 || fs[0].Severity != check.High || len([]rune(fs[0].Evidence)) != 300 {
		t.Errorf("%d %v %d", len(fs), fs[0].Severity, len([]rune(fs[0].Evidence)))
	}
}
