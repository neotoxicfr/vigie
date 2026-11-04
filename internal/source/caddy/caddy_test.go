package caddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/source"
)

func discover(t *testing.T, file string) map[string]source.Route {
	t.Helper()
	b, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	return discoverJSON(t, b)
}

func discoverJSON(t *testing.T, b []byte) map[string]source.Route {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/" {
			http.NotFound(w, r)
			return
		}
		w.Write(b)
	}))
	t.Cleanup(ts.Close)
	routes, err := New("t", ts.URL+"/").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]source.Route{}
	for _, r := range routes {
		if _, dup := out[r.Name]; dup {
			t.Fatalf("nom de route en double : %s", r.Name)
		}
		out[r.Name] = r
	}
	return out
}

func kinds(r source.Route) []source.Kind {
	var k []source.Kind
	for _, m := range r.Middlewares {
		k = append(k, m.Kind)
	}
	return k
}

func TestName(t *testing.T) {
	if got := New("x", "http://a").Name(); got != "caddy/x" {
		t.Fatal(got)
	}
}

func TestDiscover(t *testing.T) {
	rs := discover(t, "config.json")
	pre := func(s ...string) []netip.Prefix {
		var o []netip.Prefix
		for _, x := range s {
			o = append(o, netip.MustParsePrefix(x))
		}
		return o
	}
	cases := []struct {
		name     string
		tls      bool
		ports    []int
		kinds    []source.Kind
		backends []string
		declared []string
		problem  string // sous-chaîne attendue
	}{
		{"srv0/app.example.com", true, []int{443}, []source.Kind{source.IPAllow}, []string{"http://192.0.2.10:8080"}, []string{"remote_ip"}, ""},
		{"srv0/auth.example.com", true, []int{443}, []source.Kind{source.BasicAuth, source.Headers}, []string{"http://192.0.2.11:3000"}, []string{"authentication", "headers"}, ""},
		{"srv0/sso.example.com", true, []int{443}, []source.Kind{source.ForwardAuth}, []string{"http://192.0.2.12:80"}, []string{"forward_auth"}, ""},
		{"srv0/old.example.com", true, []int{443}, []source.Kind{source.Redirect}, nil, nil, ""},
		{"srv0/lan.example.com", true, []int{443}, []source.Kind{source.IPAllow}, []string{"http://192.0.2.14:80"}, nil, ""},
		{"srv0/rl.example.com", true, []int{443}, []source.Kind{source.RateLimit}, []string{"https://192.0.2.15:80"}, nil, ""},
		{"srv0/php.example.com", true, []int{443}, nil, []string{"fastcgi://192.0.2.16:9000"}, nil, ""},
		{"srv0/multi.example.com", true, []int{443}, nil, []string{"http://192.0.2.17:8000"}, nil, ""},
		{"srv0/multi.example.com#2", true, []int{443}, nil, []string{"http://192.0.2.18:8001"}, nil, ""},
		{"srv0/*", true, []int{443}, nil, []string{"http://192.0.2.13:80"}, nil, "host non littéral"},
		{"srv1/plain.example.com", false, []int{80}, nil, nil, nil, ""},
		{"srv2/internal.example.net", true, []int{8443, 8444}, nil, []string{"http://192.0.2.20:80"}, nil, ""},
		{"srv3/skip.example.org", false, []int{8080}, nil, []string{"http://192.0.2.21:80"}, nil, ""},
		{"srv3/203.0.113.5", false, []int{8080}, nil, []string{"http://192.0.2.22:80"}, nil, ""},
	}
	for _, c := range cases {
		r, ok := rs[c.name]
		if !ok {
			t.Errorf("%s : route absente (routes : %v)", c.name, keys(rs))
			continue
		}
		if r.TLS != c.tls || !reflect.DeepEqual(r.Ports, c.ports) || !reflect.DeepEqual(kinds(r), c.kinds) ||
			!reflect.DeepEqual(r.Backends, c.backends) || (c.declared != nil && !reflect.DeepEqual(r.Declared, c.declared)) {
			t.Errorf("%s : tls=%v ports=%v kinds=%v backends=%v declared=%v", c.name, r.TLS, r.Ports, kinds(r), r.Backends, r.Declared)
		}
		if c.problem != "" && !strings.Contains(strings.Join(r.Problems, "|"), c.problem) {
			t.Errorf("%s : problème %q attendu, obtenu %v", c.name, c.problem, r.Problems)
		}
	}
	// Garde « not remote_ip » : les plages sont les autorisées.
	if got := rs["srv0/app.example.com"].Middlewares[0].AllowFrom; !reflect.DeepEqual(got, pre("192.0.2.0/24", "2001:db8::/32")) {
		t.Errorf("AllowFrom = %v", got)
	}
	// Garde « remote_ip » (refus) : autorisées = complément, sans la plage refusée.
	al := rs["srv0/lan.example.com"].Middlewares[0].AllowFrom
	deny := netip.MustParsePrefix("198.51.100.0/24")
	for _, p := range al {
		if p.Overlaps(deny) {
			t.Errorf("le complément recouvre la plage refusée : %v", p)
		}
	}
	if len(al) != 24+1 /* v4 : 24 moitiés */ {
		t.Errorf("complément : %d préfixes", len(al))
	}
	if a := rs["srv0/sso.example.com"].Middlewares[0].AuthURL; a != "http://authelia.example.net:9091/api/authz/forward-auth" {
		t.Errorf("AuthURL = %q", a)
	}
	// Le chemin d'une sous-route est porté par la route.
	if p := rs["srv0/multi.example.com"].Paths; !reflect.DeepEqual(p, []string{"/api/*"}) {
		t.Errorf("Paths = %v", p)
	}
	// La route attrape-tout (static_response 200 sans host).
	var catch bool
	for _, r := range rs {
		if len(r.Hosts) == 0 && strings.Contains(strings.Join(r.Problems, "|"), "aucun host") {
			catch = true
		}
	}
	if !catch {
		t.Error("route sans host non signalée")
	}
}

func keys(m map[string]source.Route) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

func TestComplement(t *testing.T) {
	got, ok := complement([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if !ok || len(got) != 8+1 { // 8 moitiés IPv4 + ::/0
		t.Fatalf("%d %v", len(got), got)
	}
	got, _ = complement([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")})
	if len(got) != 0 {
		t.Fatalf("tout refusé : %v", got)
	}
}

func TestErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"404":    func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"json":   func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("{")) },
		"énorme": func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, maxBody+10)) },
	}
	for n, h := range cases {
		ts := httptest.NewServer(h)
		_, err := New("t", ts.URL).Discover(context.Background())
		ts.Close()
		if err == nil || !strings.HasPrefix(err.Error(), "caddy/t") {
			t.Errorf("%s : erreur attendue, obtenu %v", n, err)
		}
	}
}

// Un refus conditionné par la méthode n'est pas une liste blanche : GET reste public.
func TestConditionalGuard(t *testing.T) {
	const cfg = `{"apps":{"http":{"servers":{"s":{"listen":[":443"],"routes":[{"match":[{"host":["post.example.com"]}],
"handle":[{"handler":"subroute","routes":[
 {"match":[{"method":["POST"],"not":[{"remote_ip":{"ranges":["192.0.2.0/24"]}}]}],"handle":[{"handler":"static_response","status_code":403}]},
 {"match":[{"not":[{"remote_ip":{"ranges":["198.51.100.0/24"]},"method":["GET"]}]}],"handle":[{"handler":"static_response","status_code":403}]},
 {"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"192.0.2.10:8080"}]}]}]}],"terminal":true}]}}}}}`
	rs := discoverJSON(t, []byte(cfg))
	if len(rs) != 1 {
		t.Fatalf("routes : %v", keys(rs))
	}
	for _, r := range rs {
		for _, m := range r.Middlewares {
			if m.Kind == source.IPAllow {
				t.Errorf("garde conditionnelle prise pour une liste blanche : %+v", m)
			}
		}
		others := 0
		for _, m := range r.Middlewares {
			if m.Name == "remote_ip" && m.Kind == source.Other {
				others++
			}
		}
		if others != 2 || !strings.Contains(strings.Join(r.Problems, "|"), "garde IP conditionnelle") {
			t.Errorf("%d gardes Other, problèmes : %v", others, r.Problems)
		}
	}
}
