package nginx

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/source"
)

func routes(t *testing.T, dir string) map[string]source.Route {
	t.Helper()
	rs, err := New("t", dir).Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]source.Route{}
	for _, r := range rs {
		if _, dup := out[r.Name]; dup {
			t.Fatalf("nom en double : %s", r.Name)
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

func pfx(s ...string) []netip.Prefix {
	var o []netip.Prefix
	for _, x := range s {
		o = append(o, netip.MustParsePrefix(x))
	}
	return o
}

func TestName(t *testing.T) {
	if New("x", ".").Name() != "nginx/x" {
		t.Fatal("nom")
	}
}

func TestDiscover(t *testing.T) {
	rs := routes(t, "testdata/site")
	cases := []struct {
		name     string
		hosts    []string
		paths    []string
		ports    []int
		tls      bool
		kinds    []source.Kind
		backends []string
		problem  string
	}{
		{"example.com:80", []string{"example.com", "www.example.com"}, nil, []int{80}, false, []source.Kind{source.Headers, source.Redirect}, nil, ""},
		{"app.example.com:443", []string{"app.example.com"}, nil, []int{443}, true, []source.Kind{source.Headers},
			[]string{"http://192.0.2.10:8080", "http://192.0.2.11:8080", "http://192.0.2.15:9000"}, ""},
		{"app.example.com:443 location /admin/", []string{"app.example.com"}, []string{"/admin/"}, []int{443}, true,
			[]source.Kind{source.IPAllow, source.Headers}, []string{"http://192.0.2.12:9000"}, ""},
		{"app.example.com:443 location /private/", []string{"app.example.com"}, []string{"/private/"}, []int{443}, true,
			[]source.Kind{source.BasicAuth, source.Headers}, []string{"http://192.0.2.13:9000"}, ""},
		{"app.example.com:443 location /sso/", []string{"app.example.com"}, []string{"/sso/"}, []int{443}, true,
			[]source.Kind{source.ForwardAuth, source.Headers}, []string{"http://192.0.2.14:9000"}, ""},
		{"app.example.com:443 location ~ ^/regex/", []string{"app.example.com"}, nil, []int{443}, true,
			[]source.Kind{source.IPAllow, source.Headers}, nil, "location regex"},
		{"*.example.com:8443", []string{"wild.example.org"}, nil, []int{8443}, true,
			[]source.Kind{source.Headers, source.RateLimit}, nil, "server_name non littéral"},
		{"lan.example.net:8080", []string{"lan.example.net"}, nil, []int{8080}, false,
			[]source.Kind{source.IPAllow, source.Headers}, []string{"grpc://192.0.2.30:50051", "fastcgi://192.0.2.31:9000"}, ""},
		{"nolisten.example.org:80", []string{"nolisten.example.org"}, nil, []int{80}, false,
			[]source.Kind{source.Headers, source.Redirect}, nil, "proxy_pass dynamique"},
		{"both.example.org:9000", []string{"both.example.org"}, nil, []int{9000}, false,
			[]source.Kind{source.IPAllow, source.BasicAuth, source.Headers}, []string{"http://192.0.2.40:80"}, "satisfy any"},
	}
	for _, c := range cases {
		r, ok := rs[c.name]
		if !ok {
			t.Errorf("%s : absente (%v)", c.name, names(rs))
			continue
		}
		if !reflect.DeepEqual(r.Hosts, c.hosts) || !reflect.DeepEqual(r.Paths, c.paths) || !reflect.DeepEqual(r.Ports, c.ports) ||
			r.TLS != c.tls || !reflect.DeepEqual(kinds(r), c.kinds) || !reflect.DeepEqual(r.Backends, c.backends) {
			t.Errorf("%s : hosts=%v paths=%v ports=%v tls=%v kinds=%v backends=%v", c.name, r.Hosts, r.Paths, r.Ports, r.TLS, kinds(r), r.Backends)
		}
		if c.problem != "" && !strings.Contains(strings.Join(r.Problems, "|"), c.problem) {
			t.Errorf("%s : problème %q attendu, obtenu %v", c.name, c.problem, r.Problems)
		}
	}
	// Le serveur app ne répète pas l'accès des locations isolées dans ses propres middlewares.
	if got := rs["app.example.com:443 location /admin/"].Middlewares[0].AllowFrom; !reflect.DeepEqual(got, pfx("192.0.2.0/24", "2001:db8::/32")) {
		t.Errorf("AllowFrom /admin/ = %v", got)
	}
	// Refus puis « allow all » : le complément ne recouvre pas la plage refusée.
	deny := netip.MustParsePrefix("198.51.100.0/24")
	for _, p := range rs["lan.example.net:8080"].Middlewares[0].AllowFrom {
		if p.Overlaps(deny) {
			t.Errorf("autorisé recouvre le refus : %v", p)
		}
	}
	// satisfy any : la liste est contournable par l'authentification ; pas ailleurs.
	if !rs["both.example.org:9000"].Middlewares[0].OrAuth || rs["lan.example.net:8080"].Middlewares[0].OrAuth {
		t.Error("OrAuth mal posé")
	}
	if got := rs["app.example.com:443 location /sso/"].Middlewares[0].AuthURL; got != "http://192.0.2.20:9091" {
		t.Errorf("AuthURL = %q", got)
	}
	// Le serveur lui-même n'a pas de backend interne (location /auth interne exclue).
	for _, b := range rs["app.example.com:443"].Backends {
		if strings.Contains(b, "9091") {
			t.Error("location interne dans les backends")
		}
	}
	if got := rs["example.com:80"].Declared; !reflect.DeepEqual(got, []string{"add_header", "return"}) {
		t.Errorf("Declared = %v", got)
	}
}

func names(m map[string]source.Route) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	return k
}

func TestAllowed(t *testing.T) {
	a := func(s string) []netip.Prefix { return parseAddr(s) }
	cases := []struct {
		name       string
		rules      []rule
		want       []netip.Prefix
		restricted bool
	}{
		{"allow puis deny all", []rule{{true, a("10.0.0.0/8")}, {false, a("all")}}, pfx("10.0.0.0/8"), true},
		{"deny précis avant allow", []rule{{false, a("10.0.0.5")}, {true, a("10.0.0.0/8")}, {false, a("all")}}, nil, true},
		{"allow seul", []rule{{true, a("10.0.0.0/8")}}, nil, false},
		{"deny all puis allow : inatteignable", []rule{{false, a("all")}, {true, a("10.0.0.0/8")}}, nil, true},
	}
	for _, c := range cases {
		got, restricted, ok := allowed(c.rules)
		if !ok || restricted != c.restricted {
			t.Errorf("%s : restricted=%v ok=%v", c.name, restricted, ok)
		}
		switch c.name {
		case "allow puis deny all":
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("%s : %v", c.name, got)
			}
		case "deny précis avant allow":
			for _, p := range got {
				if p.Contains(netip.MustParseAddr("10.0.0.5")) {
					t.Errorf("10.0.0.5 autorisée par %v", p)
				}
			}
			if len(got) != 24 { // 10/8 moins une adresse : 24 morceaux
				t.Errorf("%d morceaux", len(got))
			}
		case "deny all puis allow : inatteignable":
			if len(got) != 0 {
				t.Errorf("%v", got)
			}
		}
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestHostile(t *testing.T) {
	big := strings.Repeat("#", maxFileSize+1)
	chain := func(dir string, n int) {
		for i := 0; i < n; i++ {
			write(t, filepath.Join(dir, fmt.Sprintf("c%d.conf", i)), fmt.Sprintf("include c%d.conf;\n", i+1))
		}
		write(t, filepath.Join(dir, fmt.Sprintf("c%d.conf", n)), "# fin\n")
	}
	cases := []struct {
		name  string
		setup func(dir string)
		want  string
	}{
		{"include ../", func(d string) {
			write(t, filepath.Join(d, "..", "outside.conf"), "# dehors\n")
			write(t, filepath.Join(d, "nginx.conf"), "include ../outside.conf;\n")
		}, "hors du dossier"},
		{"include absolu hors dossier", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include /etc/passwd;\n")
		}, "hors du dossier"},
		{"lien symbolique sortant", func(d string) {
			out := filepath.Join(d, "..", "secret.conf")
			write(t, out, "# secret\n")
			write(t, filepath.Join(d, "nginx.conf"), "include link.conf;\n")
			if err := os.Symlink(out, filepath.Join(d, "link.conf")); err != nil {
				t.Skip(err)
			}
		}, "sort du dossier"},
		{"répertoire lié sortant (glob)", func(d string) {
			out := filepath.Join(d, "..", "outdir")
			write(t, filepath.Join(out, "a.conf"), "# a\n")
			write(t, filepath.Join(d, "nginx.conf"), "include sub/*.conf;\n")
			if err := os.Symlink(out, filepath.Join(d, "sub")); err != nil {
				t.Skip(err)
			}
		}, "sort du dossier"},
		{"fichier énorme", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include big.conf;\n")
			write(t, filepath.Join(d, "big.conf"), big)
		}, "fichier >"},
		{"boucle", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include a.conf;\n")
			write(t, filepath.Join(d, "a.conf"), "include b.conf;\n")
			write(t, filepath.Join(d, "b.conf"), "include a.conf;\n")
		}, "boucle d'include"},
		{"profondeur", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include c0.conf;\n")
			chain(d, maxIncludeDep+2)
		}, "include imbriqués"},
		{"trop de fichiers", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include conf.d/*.conf;\n")
			for i := 0; i <= maxFiles; i++ {
				write(t, filepath.Join(d, "conf.d", fmt.Sprintf("f%03d.conf", i)), fmt.Sprintf("# %d\n", i))
			}
		}, "plus de 200 fichiers"},
		{"taille totale", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include conf.d/*.conf;\n")
			for i := 0; i < 17; i++ {
				write(t, filepath.Join(d, "conf.d", fmt.Sprintf("f%02d.conf", i)), strings.Repeat("#", maxFileSize-1)+"\n")
			}
		}, "au total"},
		{"explosion d'inclusions", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), strings.Repeat("include a.conf;\n", 100))
			write(t, filepath.Join(d, "a.conf"), strings.Repeat("include b.conf;\n", 100))
			write(t, filepath.Join(d, "b.conf"), strings.Repeat("include c.conf;\n", 100))
			write(t, filepath.Join(d, "c.conf"), "# fin\n")
		}, "inclusions développées"},
		{"imbrication", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), strings.Repeat("a {", 5000)+strings.Repeat("}", 5000))
		}, "blocs imbriqués"},
		{"include avec variable", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include $x.conf;\n")
		}, "variable"},
		{"include manquant", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "include nope.conf;\n")
		}, "introuvable"},
		{"syntaxe", func(d string) {
			write(t, filepath.Join(d, "nginx.conf"), "http { server { listen 80 }\n")
		}, "nginx.conf"},
		{"nginx.conf absent", func(d string) {}, "nginx.conf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "conf")
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			c.setup(dir)
			_, err := New("t", dir).Discover(context.Background())
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "nginx/t") {
				t.Fatalf("erreur %q attendue, obtenu %v", c.want, err)
			}
		})
	}
}

func TestSharedSnippetAndHidden(t *testing.T) {
	d := t.TempDir()
	write(t, filepath.Join(d, "nginx.conf"), "http { server { listen 81; server_name a.example.org; include snip.conf; } server { listen 82; server_name b.example.org; include snip.conf; include conf/*.conf; } }\n")
	write(t, filepath.Join(d, "snip.conf"), "location / { proxy_pass http://192.0.2.50:80; }\n")
	write(t, filepath.Join(d, "conf", ".cache.conf"), "this is not nginx\n") // caché : ignoré par le joker
	write(t, filepath.Join(d, "conf", "ok.conf"), "add_header X-A 1;\n")
	rs := routes(t, d)
	if len(rs) != 2 || !reflect.DeepEqual(rs["a.example.org:81"].Backends, []string{"http://192.0.2.50:80"}) ||
		!reflect.DeepEqual(rs["b.example.org:82"].Backends, []string{"http://192.0.2.50:80"}) {
		t.Fatalf("%+v", rs)
	}
}
