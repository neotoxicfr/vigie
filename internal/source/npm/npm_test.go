package npm

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/source"
)

// Schéma réel de NPM (migrations de NginxProxyManager/nginx-proxy-manager,
// backend/migrations), réduit aux colonnes utiles.
const schema = `
CREATE TABLE proxy_host (id integer PRIMARY KEY AUTOINCREMENT, is_deleted integer NOT NULL DEFAULT 0, domain_names json NOT NULL,
  forward_host varchar(255) NOT NULL, forward_port integer NOT NULL, access_list_id integer NOT NULL DEFAULT 0,
  certificate_id integer NOT NULL DEFAULT 0, ssl_forced integer NOT NULL DEFAULT 0, advanced_config text NOT NULL DEFAULT '',
  forward_scheme varchar(255) NOT NULL DEFAULT 'http', enabled integer NOT NULL DEFAULT 1,
  hsts_enabled integer NOT NULL DEFAULT 0, hsts_subdomains integer NOT NULL DEFAULT 0, locations json);
CREATE TABLE redirection_host (id integer PRIMARY KEY AUTOINCREMENT, is_deleted integer NOT NULL DEFAULT 0, domain_names json NOT NULL,
  forward_domain_name varchar(255) NOT NULL, preserve_path integer NOT NULL DEFAULT 0, certificate_id integer NOT NULL DEFAULT 0,
  ssl_forced integer NOT NULL DEFAULT 0, advanced_config text NOT NULL DEFAULT '', enabled integer NOT NULL DEFAULT 1,
  hsts_enabled integer NOT NULL DEFAULT 0, hsts_subdomains integer NOT NULL DEFAULT 0,
  forward_scheme varchar(255) NOT NULL DEFAULT 'auto', forward_http_code integer NOT NULL DEFAULT 302);
CREATE TABLE dead_host (id integer PRIMARY KEY AUTOINCREMENT, is_deleted integer NOT NULL DEFAULT 0, domain_names json NOT NULL,
  certificate_id integer NOT NULL DEFAULT 0, ssl_forced integer NOT NULL DEFAULT 0, advanced_config text NOT NULL DEFAULT '',
  enabled integer NOT NULL DEFAULT 1, hsts_enabled integer NOT NULL DEFAULT 0, hsts_subdomains integer NOT NULL DEFAULT 0);
CREATE TABLE stream (id integer PRIMARY KEY AUTOINCREMENT, is_deleted integer NOT NULL DEFAULT 0, incoming_port integer NOT NULL,
  forwarding_host varchar(255) NOT NULL, forwarding_port integer NOT NULL, tcp_forwarding integer NOT NULL DEFAULT 0,
  udp_forwarding integer NOT NULL DEFAULT 0, enabled integer NOT NULL DEFAULT 1, certificate_id integer NOT NULL DEFAULT 0);
CREATE TABLE access_list (id integer PRIMARY KEY AUTOINCREMENT, is_deleted integer NOT NULL DEFAULT 0, name varchar(255) NOT NULL,
  satisfy_any integer NOT NULL DEFAULT 0, pass_auth integer NOT NULL DEFAULT 1);
CREATE TABLE access_list_auth (id integer PRIMARY KEY AUTOINCREMENT, access_list_id integer NOT NULL, username varchar(255) NOT NULL, password varchar(255) NOT NULL);
CREATE TABLE access_list_client (id integer PRIMARY KEY AUTOINCREMENT, access_list_id integer NOT NULL, address varchar(255) NOT NULL, directive varchar(255) NOT NULL);
INSERT INTO access_list (id, name, satisfy_any) VALUES (1, 'interne', 0), (2, 'mixte', 1), (3, 'supprimée', 0);
UPDATE access_list SET is_deleted = 1 WHERE id = 3;
INSERT INTO access_list_client (access_list_id, address, directive) VALUES (1, '192.0.2.0/24', 'allow'), (1, '2001:db8::/32', 'allow'), (1, 'all', 'deny'),
  (2, '203.0.113.7', 'allow'), (2, 'all', 'deny');
INSERT INTO access_list_auth (access_list_id, username, password) VALUES (2, 'neo', '$2y$10$hashfactice');
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, forward_scheme) VALUES (1, '["plain.example.com"]', '192.0.2.10', 8080, 'http');
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, forward_scheme, certificate_id, ssl_forced, hsts_enabled, hsts_subdomains, access_list_id)
  VALUES (2, '["secure.example.com","www.secure.example.com"]', '192.0.2.11', 8443, 'https', 5, 1, 1, 1, 1);
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, enabled) VALUES (3, '["off.example.com"]', '192.0.2.12', 80, 0);
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, is_deleted) VALUES (4, '["gone.example.com"]', '192.0.2.13', 80, 1);
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, advanced_config, locations, access_list_id, certificate_id)
  VALUES (5, '["*.example.org","adv.example.org"]', '192.0.2.14', 80, 'proxy_buffering off;',
  '[{"path":"/api","forward_scheme":"http","forward_host":"192.0.2.15","forward_port":9000}]', 2, 7);
INSERT INTO proxy_host (id, domain_names, forward_host, forward_port, access_list_id) VALUES (6, '["dangling.example.com"]', '192.0.2.16', 80, 3);
INSERT INTO redirection_host (id, domain_names, forward_domain_name, forward_scheme, forward_http_code, certificate_id, ssl_forced)
  VALUES (1, '["old.example.com"]', 'new.example.com', 'https', 301, 5, 0);
INSERT INTO dead_host (id, domain_names, certificate_id) VALUES (1, '["dead.example.com"]', 0);
INSERT INTO stream (id, incoming_port, forwarding_host, forwarding_port, tcp_forwarding, udp_forwarding) VALUES (1, 2222, '192.0.2.20', 22, 1, 0), (2, 5353, '192.0.2.21', 53, 1, 1);
`

func newDB(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "database.sqlite")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	return p
}

func kinds(r source.Route) []source.Kind {
	var k []source.Kind
	for _, m := range r.Middlewares {
		k = append(k, m.Kind)
	}
	return k
}

func TestDiscover(t *testing.T) {
	p := newDB(t)
	dir := filepath.Dir(p)
	before := sha256.Sum256(mustRead(t, p))
	n := New("nas", p)
	if n.Name() != "npm/nas" {
		t.Fatal(n.Name())
	}
	rs, err := n.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]source.Route{}
	for _, r := range rs {
		got[r.Name] = r
	}
	cases := []struct {
		name     string
		hosts    []string
		ports    []int
		tls      bool
		kinds    []source.Kind
		backends []string
		problem  string
	}{
		{"plain.example.com (proxy_host 1)", []string{"plain.example.com"}, []int{80}, false, nil, []string{"http://192.0.2.10:8080"}, ""},
		{"secure.example.com (proxy_host 2)", []string{"secure.example.com", "www.secure.example.com"}, []int{80, 443}, true,
			[]source.Kind{source.Redirect, source.Headers, source.IPAllow}, []string{"https://192.0.2.11:8443"}, ""},
		{"*.example.org (proxy_host 5)", []string{"adv.example.org"}, []int{80, 443}, true,
			[]source.Kind{source.IPAllow, source.BasicAuth}, []string{"http://192.0.2.14:80", "http://192.0.2.15:9000"}, "config avancée non analysée"},
		{"dangling.example.com (proxy_host 6)", []string{"dangling.example.com"}, []int{80}, false, nil, []string{"http://192.0.2.16:80"}, "introuvable ou supprimée"},
		{"old.example.com (redirection_host 1)", []string{"old.example.com"}, []int{80, 443}, true, []source.Kind{source.Redirect}, nil, ""},
		{"dead.example.com (dead_host 1)", []string{"dead.example.com"}, []int{80}, false, nil, nil, ""},
		{"stream 2222 (stream 1)", nil, []int{2222}, false, nil, []string{"tcp://192.0.2.20:22"}, ""},
		{"stream 5353 (stream 2)", nil, []int{5353}, false, nil, []string{"tcp://192.0.2.21:53", "udp://192.0.2.21:53"}, ""},
	}
	for _, c := range cases {
		r, ok := got[c.name]
		if !ok {
			t.Errorf("%s absente", c.name)
			continue
		}
		if !reflect.DeepEqual(r.Hosts, c.hosts) || !reflect.DeepEqual(r.Ports, c.ports) || r.TLS != c.tls ||
			!reflect.DeepEqual(kinds(r), c.kinds) || !reflect.DeepEqual(r.Backends, c.backends) {
			t.Errorf("%s : hosts=%v ports=%v tls=%v kinds=%v backends=%v", c.name, r.Hosts, r.Ports, r.TLS, kinds(r), r.Backends)
		}
		if c.problem != "" && !strings.Contains(strings.Join(r.Problems, "|"), c.problem) {
			t.Errorf("%s : problème %q attendu, obtenu %v", c.name, c.problem, r.Problems)
		}
	}
	for _, absent := range []string{"off.example.com (proxy_host 3)", "gone.example.com (proxy_host 4)"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s ne doit pas apparaître", absent)
		}
	}
	// Liste « allow … ; deny all » : les adresses autorisées, rien d'autre.
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("2001:db8::/32")}
	if a := got["secure.example.com (proxy_host 2)"].Middlewares[2].AllowFrom; !reflect.DeepEqual(a, want) {
		t.Errorf("AllowFrom = %v", a)
	}
	// Mot de passe et nom d'utilisateur ne sortent pas.
	for _, r := range rs {
		for _, m := range r.Middlewares {
			if strings.Contains(string(m.Config), "hashfactice") || strings.Contains(string(m.Config), `"neo"`) {
				t.Errorf("secret dans la config : %s", m.Config)
			}
		}
	}
	if !strings.Contains(strings.Join(got["*.example.org (proxy_host 5)"].Problems, "|"), "satisfy any") {
		t.Error("satisfy any non signalé")
	}
	for _, r := range rs {
		for _, m := range r.Middlewares {
			if m.Kind == source.IPAllow && m.OrAuth != (r.Name == "*.example.org (proxy_host 5)") {
				t.Errorf("%s : OrAuth = %v", r.Name, m.OrAuth)
			}
		}
	}
	// Lecture seule : octets inchangés, aucun fichier créé à côté.
	if after := sha256.Sum256(mustRead(t, p)); after != before {
		t.Error("la base a été modifiée")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("fichiers créés à côté de la base : %v", ents)
	}
}

func mustRead(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOldSchemaWithoutOptionalColumns(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.sqlite")
	db, _ := sql.Open("sqlite", p)
	_, err := db.Exec(`CREATE TABLE proxy_host (id integer PRIMARY KEY, is_deleted integer DEFAULT 0, domain_names json, forward_ip text, forward_port integer, access_list_id integer, certificate_id integer, ssl_forced integer, advanced_config text);
		INSERT INTO proxy_host VALUES (1, 0, '["a.example.com"]', '192.0.2.1', 80, 0, 0, 0, '');`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	rs, err := New("x", p).Discover(context.Background())
	if err != nil || len(rs) != 1 || rs[0].Backends[0] != "http://192.0.2.1:80" {
		t.Fatalf("%v %+v", err, rs)
	}
}

func TestErrors(t *testing.T) {
	dir := t.TempDir()
	mysql := filepath.Join(dir, "mysql.txt")
	os.WriteFile(mysql, []byte("mysql://npm:secret@db/npm"), 0o600)
	other := filepath.Join(dir, "other.sqlite")
	db, _ := sql.Open("sqlite", other)
	db.Exec("CREATE TABLE t (x)")
	db.Close()
	for name, c := range map[string]struct{ path, want string }{
		"mysql":    {mysql, "MySQL"},
		"absent":   {filepath.Join(dir, "nope"), "no such file"},
		"autre db": {other, "pas une base Nginx Proxy Manager"},
	} {
		_, err := New("x", c.path).Discover(context.Background())
		if err == nil || !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "npm/x") {
			t.Errorf("%s : %v", name, err)
		}
	}
}
