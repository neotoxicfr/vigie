package authelia

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/authprov"
)

func TestDecide(t *testing.T) {
	a, err := Load("testdata/configuration.yml")
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "authelia" {
		t.Fatal(a.Name())
	}
	const anon = "192.0.2.10"
	for _, c := range []struct {
		host, path, method, ip string
		policy                 string
		rule                   int
		reason                 string
	}{
		{"public.example.com", "/", "GET", anon, "bypass", 0, ""},
		{"PUBLIC.Example.com", "/x", "GET", anon, "bypass", 0, ""},                     // casse ignorée
		{"public.example.com:8443", "/", "GET", anon, "bypass", 0, ""},                 // port ignoré
		{"a.example.org", "/", "GET", "192.168.1.2", "bypass", 1, ""},                  // réseau nommé
		{"a.example.org", "/", "GET", "2001:db8:1::5", "bypass", 1, ""},                // réseau nommé IPv6
		{"a.example.org", "/", "GET", "::ffff:192.168.1.2", "bypass", 1, ""},           // IPv4 encapsulée
		{"a.example.org", "/", "GET", anon, "one_factor", 2, ""},                       // ordre : 1re qui correspond
		{"example.org", "/", "GET", "192.168.1.2", "one_factor", 2, ""},                // *. n'inclut pas l'apex
		{"api.example.com", "/api/public/x", "get", anon, "bypass", 3, ""},             // méthode en minuscules
		{"api.example.com", "/api/public?x=1", "GET", anon, "bypass", 3, ""},           // ressource avec requête
		{"api.example.com", "/api/../api/public", "GET", anon, "bypass", 3, ""},        // chemin nettoyé
		{"api.example.com", "/api/public", "POST", anon, "one_factor", 5, "portail"},   // méthode exclue -> règle à sujet
		{"api.example.com", "/api/publicite", "GET", anon, "one_factor", 5, "portail"}, // regex ancrée par l'auteur
		{"api.example.com", "/x?token=1&mode=lecture", "GET", anon, "one_factor", 4, ""},
		{"api.example.com", "/x?token=1&mode=ecriture", "GET", anon, "one_factor", 5, "portail"}, // ET non satisfait
		{"api.example.com", "/x?v=12", "GET", anon, "one_factor", 4, ""},                         // 2e groupe (OU)
		{"api.example.com", "/x?v=12&debug=1", "GET", anon, "one_factor", 5, "portail"},          // absent non satisfait
		{"api.example.com", "/x?v=1a", "GET", anon, "one_factor", 5, "portail"},                  // pattern non satisfait
		{"bob.users.example.com", "/", "GET", anon, "two_factor", 6, "sujet"},                    // groupe User dans domain_regex
		{"bob.home.example.com", "/", "GET", anon, "one_factor", 7, "sujet"},                     // {user}
		{"home.example.com", "/", "GET", anon, "deny", -1, "défaut"},
		{"bureau.example.com", "/", "GET", "198.51.100.7", "bypass", 8, ""}, // nom -> IP seule
		{"bureau.example.com", "/", "GET", "198.51.100.8", "deny", -1, ""},  // /32
		{"bureau.example.com", "/", "GET", "203.0.113.9", "bypass", 8, ""},  // CIDR direct
		{"inconnu.example.net", "/", "GET", anon, "deny", -1, "défaut"},
	} {
		d := a.Decide(c.host, c.path, c.method, netip.MustParseAddr(c.ip))
		if d.Policy != c.policy || d.Rule != c.rule || !strings.Contains(d.Reason, c.reason) {
			t.Errorf("%s%s %s depuis %s : %+v ; attendu %s règle %d (%q)", c.host, c.path, c.method, c.ip, d, c.policy, c.rule, c.reason)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for name, y := range map[string]string{
		"politique":     "access_control: {rules: [{domain: a.example.com, policy: allow}]}",
		"défaut":        "access_control: {default_policy: open, rules: [{domain: a.example.com, policy: deny}]}",
		"sans domaine":  "access_control: {rules: [{policy: deny}]}",
		"réseau":        "access_control: {rules: [{domain: a.example.com, policy: deny, networks: [lan]}]}",
		"bypass sujet":  "access_control: {rules: [{domain: a.example.com, policy: bypass, subject: 'user:x'}]}",
		"bypass {user}": "access_control: {rules: [{domain: '{user}.example.com', policy: bypass}]}",
		"regex":         "access_control: {rules: [{domain: a.example.com, policy: deny, resources: ['(']}]}",
		"opérateur":     "access_control: {rules: [{domain: a.example.com, policy: deny, query: [[{key: a, operator: like}]]}]}",
		"sans règle":    "access_control: {default_policy: deny}",
		"yaml":          "jwt_secret: SECRET-NE-PAS-AFFICHER\n\t: [",
	} {
		_, err := Parse([]byte(y))
		if err == nil {
			t.Errorf("%s : erreur attendue", name)
		} else if strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%s : l'erreur divulgue le fichier : %v", name, err)
		}
	}
	a, err := Parse([]byte("access_control: {default_policy: two_factor}"))
	if err != nil || a.Decide("x.example.com", "/", "GET", netip.MustParseAddr("192.0.2.1")).Policy != authprov.TwoFactor {
		t.Errorf("défaut seul : %v", err)
	}
}

func TestLoadTooBig(t *testing.T) {
	f := filepath.Join(t.TempDir(), "big.yml")
	if err := os.WriteFile(f, make([]byte, maxSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(f); err == nil {
		t.Error("fichier trop gros accepté")
	}
}
