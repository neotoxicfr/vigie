package config

import (
	"strings"
	"testing"
)

const proxy = "auth:\n  proxy: {header: X, trusted_proxies: [10.0.0.0/8]}\n"

const hash = "$argon2id$v=19$m=65536,t=3,p=1$c2Vs$aGFzaA"

func TestParse(t *testing.T) {
	cases := []struct {
		name, yaml, wantErr string
	}{
		{"sans auth", "listen: ':9000'\n", "refuse de démarrer sans auth"},
		{"utilisateur ok", "auth:\n  users:\n    - {name: admin, password_hash: '" + hash + "'}\n", ""},
		{"hash en clair", "auth:\n  users:\n    - {name: admin, password_hash: secret}\n", "argon2id"},
		{"doublon", "auth:\n  users:\n    - {name: a, password_hash: '" + hash + "'}\n    - {name: a, password_hash: '" + hash + "'}\n", "en double"},
		{"proxy sans plages", "auth:\n  proxy: {header: Remote-User}\n", "trusted_proxies vide"},
		{"proxy ok", "auth:\n  proxy: {header: Remote-User, trusted_proxies: [172.16.0.0/12]}\n", ""},
		{"champ inconnu", "auth:\n  proxy: {header: X, trusted_proxies: [10.0.0.0/8]}\nlistn: ':1'\n", "listn"},
		{"traefik ok", proxy + "sources:\n  traefik:\n    - {name: nas, url: 'http://traefik:8080'}\n", ""},
		{"traefik url", proxy + "sources:\n  traefik:\n    - {name: nas, url: 'traefik:8080'}\n", "url http(s)"},
		{"traefik identifiants dans l'url", proxy + "sources:\n  traefik:\n    - {name: nas, url: 'http://u:p@traefik'}\n", "sans identifiants"},
		{"traefik doublon", proxy + "sources:\n  traefik:\n    - {name: a, url: 'http://t'}\n    - {name: a, url: 'http://u'}\n", "en double"},
		{"traefik mdp seul", proxy + "sources:\n  traefik:\n    - {name: a, url: 'http://t', password_file: /x}\n", "vont ensemble"},
		{"sources nommées", proxy + "sources:\n  nginx:\n    - {name: a, location: /etc/nginx}\n  caddy:\n    - {name: c, location: 'http://caddy:2019'}\n", ""},
		{"caddy sans url", proxy + "sources:\n  caddy:\n    - {name: c, location: /x}\n", "API admin"},
		{"npm sans location", proxy + "sources:\n  npm:\n    - {name: n}\n", "location requis"},
		{"port hors plage", proxy + "scan: {ports: [0]}\n", "hors de 1-65535"},
		{"timeout invalide", proxy + "scan: {timeout: deux}\n", "durée invalide"},
		{"modèle inconnu", proxy + "policy: {route_templates: {'*': admin}}\n", "modèle inconnu"},
		{"sortie ok", proxy + "vantages:\n  proxies:\n    - {name: vpn, url: 'http://gluetun:8888', username: u, password_file: /run/secrets/p}\n", ""},
		{"sortie nom réservé", proxy + "vantages:\n  proxies:\n    - {name: public, url: 'socks5://x:1080'}\n", "nom unique"},
		{"sortie identifiants dans l'url", proxy + "vantages:\n  proxies:\n    - {name: vpn, url: 'http://u:p@x:8888'}\n", "sans identifiants"},
		{"sortie schéma", proxy + "vantages:\n  proxies:\n    - {name: vpn, url: 'ftp://x'}\n", "socks5://"},
		{"plage invalide", "auth:\n  proxy: {header: X, trusted_proxies: [pas-une-plage]}\n", "pas-une-plage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := Parse([]byte(c.yaml))
			if c.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Listen != ":8080" || cfg.DataDir != "/data" {
					t.Errorf("défauts : %q %q", cfg.Listen, cfg.DataDir)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("erreur %v, attendu %q", err, c.wantErr)
			}
		})
	}
}

// L'exemple livré doit rester valide : seule l'absence d'auth, voulue, est refusée.
func TestExampleConfig(t *testing.T) {
	_, err := Load("../../config.example.yaml")
	if err == nil || strings.Count(err.Error(), "\n") != 0 || !strings.Contains(err.Error(), "sans auth") {
		t.Fatalf("exemple : %v", err)
	}
}

func TestPagesValidated(t *testing.T) {
	for pg, ok := range map[string]bool{"/browser/x/cool.html": true, "/a?b=1": true, "//evil.example/x": false, "https://evil.example/": false, "rel/x": false} {
		r := DefaultRuntime()
		r.Scan.Pages = map[string]string{"office.example.com": pg}
		if err := r.Validate(); (err == nil) != ok {
			t.Errorf("%q : %v", pg, err)
		}
	}
}
