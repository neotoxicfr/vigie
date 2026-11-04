package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/cdnprov"
	"github.com/neotoxicfr/vigie/internal/check"
)

const token = "tok-SECRET-0123456789" // valeur factice de test gitleaks:allow

func ok(w http.ResponseWriter, result any, page, total int) {
	env := map[string]any{"success": true, "errors": []any{}, "result": result}
	if total > 0 {
		env["result_info"] = map[string]int{"page": page, "total_pages": total}
	}
	json.NewEncoder(w).Encode(env)
}

func fail(w http.ResponseWriter, status, code int, msg string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"success": false,
		"errors": []map[string]any{{"code": code, "message": msg}}})
}

type rec struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

var records = []rec{
	{"www.example.com", "A", "198.51.100.7", true},
	{"api.example.com", "A", "198.51.100.7", false},
	{"cloud.example.com", "CNAME", "elsewhere.example.net", false},
	{"example.com", "MX", "198.51.100.7", false},
	{"mail.example.com", "AAAA", "2001:db8::5", false},
	{"www.example.com", "AAAA", "2001:db8::7", true},
	{"dev.example.com", "AAAA", "2001:db8::7", false}, // origine déduite du www proxifié
	{"old.example.com", "A", "203.0.113.9", false},    // origine apprise dans example.net, lue après
}

func fakeAPI(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			fail(w, http.StatusForbidden, 9109, "Invalid access token")
			return
		}
		p := r.URL.Path
		switch {
		case p == "/zones":
			switch r.URL.Query().Get("name") {
			case "example.com":
				ok(w, []map[string]string{{"id": "z1", "name": "example.com"}}, 1, 1)
			case "example.net":
				ok(w, []map[string]string{{"id": "z3", "name": "example.net"}}, 1, 1)
			default:
				ok(w, []any{}, 1, 1)
			}
		case strings.HasPrefix(p, "/zones/z3/settings/"):
			fail(w, http.StatusForbidden, 9109, "Unauthorized to access requested resource")
		case p == "/zones/z3/dnssec":
			// Message qui citerait le jeton : il ne doit pas ressortir.
			fail(w, http.StatusInternalServerError, 1000, "boom "+token)
		case p == "/zones/z3/dns_records":
			ok(w, []rec{{"a.example.net", "A", "203.0.113.9", true}}, 1, 1)
		case strings.HasPrefix(p, "/zones/z3/"):
			fail(w, http.StatusNotFound, 7003, "not found")
		case p == "/zones/z1/settings/ssl":
			ok(w, map[string]any{"id": "ssl", "value": "flexible"}, 0, 0)
		case p == "/zones/z1/settings/min_tls_version":
			ok(w, map[string]any{"id": "min_tls_version", "value": "1.0"}, 0, 0)
		case p == "/zones/z1/settings/always_use_https":
			ok(w, map[string]any{"id": "always_use_https", "value": "off"}, 0, 0)
		case p == "/zones/z1/settings/security_header":
			ok(w, map[string]any{"id": "security_header", "value": map[string]any{
				"strict_transport_security": map[string]any{"enabled": false, "max_age": 0}}}, 0, 0)
		case p == "/zones/z1/origin_tls_client_auth/settings":
			w.WriteHeader(http.StatusAccepted) // comme l'API réelle (vu le 23/10)
			ok(w, map[string]any{"enabled": false}, 0, 0)
		case p == "/zones/z1/dnssec":
			ok(w, map[string]any{"status": "disabled"}, 0, 0)
		case p == "/zones/z1/dns_records":
			// Pages de 2, quel que soit per_page, pour exercer la pagination.
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if r.URL.Query().Get("per_page") != "100" || page < 1 {
				t.Errorf("pagination : %s", r.URL.RawQuery)
			}
			lo, hi := (page-1)*2, min(page*2, len(records))
			ok(w, records[lo:hi], page, (len(records)+1)/2)
		case p == "/zones/z1/rulesets/phases/http_request_firewall_custom/entrypoint":
			ok(w, map[string]any{"rules": []map[string]any{
				{"action": "block", "expression": `(not ip.geoip.country in {"FR" "BE"})`, "description": "géo", "enabled": true},
				{"action": "block", "expression": `(not cf.client.bot and http.user_agent contains "curl")`, "description": "robots", "enabled": true},
				{"action": "skip", "expression": `true`, "description": "désactivée", "enabled": false},
			}}, 0, 0)
		default:
			fail(w, http.StatusNotFound, 7003, "not found")
		}
	}))
}

func tokenFile(t *testing.T, content string) string {
	f := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(f, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func byKey(fs []check.Finding) map[string]check.Finding {
	m := map[string]check.Finding{}
	for _, f := range fs {
		m[f.Check+"@"+f.Target] = f
	}
	return m
}

var hosts = []string{"www.example.com", "api.example.com", "Cloud.Example.com.", "x.example.org", "a.example.net", "192.0.2.1"}

func TestScan(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	cf := New(tokenFile(t, "  "+token+"\n"), srv.URL+"/")
	res, err := cf.Scan(context.Background(), hosts)
	if err == nil || !strings.Contains(err.Error(), "dnssec") {
		t.Errorf("erreur attendue sur dnssec de example.net : %v", err)
	}
	if err != nil && strings.Contains(err.Error(), token) {
		t.Fatalf("le jeton fuit dans l'erreur : %v", err)
	}
	got := byKey(res.Findings)
	want := map[string]check.Severity{
		"cf.ssl.flexible@example.com":           check.High,
		"cf.tls.min@example.com":                check.Medium,
		"cf.https.not-forced@example.com":       check.Medium,
		"cf.hsts.off@example.com":               check.Info,
		"cf.aop.off@example.com":                check.Low,
		"cf.dnssec.off@example.com":             check.Low,
		"cf.dns.origin-exposed@api.example.com": check.High,
		"cf.dns.origin-exposed@dev.example.com": check.High,
		"cf.dns.origin-exposed@old.example.com": check.High,
		"cf.dns.unproxied@example.com":          check.Info,
		"cf.waf.summary@example.com":            check.Info,
		"cf.zone.missing@example.org":           check.Info,
		"cf.waf.summary@example.net":            check.Info,
		"cf.token.scope@example.net":            check.Medium,
	}
	for k, sev := range want {
		f, ok := got[k]
		if !ok {
			t.Errorf("constat manquant : %s", k)
			continue
		}
		if f.Severity != sev || f.Vantage != "config" {
			t.Errorf("%s : sévérité %v, vue %q", k, f.Severity, f.Vantage)
		}
		if strings.Contains(f.Evidence, token) {
			t.Errorf("%s : le jeton fuit dans la preuve", k)
		}
	}
	if len(got) != len(want) {
		t.Errorf("constats en trop : %v", got)
	}
	if e := got["cf.token.scope@example.net"].Evidence; !strings.Contains(e, "Zone Settings Read") {
		t.Errorf("permission manquante non nommée : %q", e)
	}
	if e := got["cf.dns.unproxied@example.com"].Evidence; e != "cloud.example.com, mail.example.com" {
		t.Errorf("non proxifiés : %q", e)
	}
	if fmt.Sprint(res.Origins) != "[198.51.100.7 2001:db8::7 203.0.113.9]" {
		t.Errorf("origines déduites : %v", res.Origins)
	}
	if !res.Proxied["www.example.com"] || res.Proxied["api.example.com"] || res.Proxied["cloud.example.com"] {
		t.Errorf("Proxied : %v", res.Proxied)
	}
	note := res.Notes["www.example.com"]
	for _, s := range []string{"Cloudflare : ", "pays autorisés FR, BE", "robots non vérifiés bloqués", `user agents "curl"`, `règle "géo" (block)`} {
		if !strings.Contains(note, s) {
			t.Errorf("note sans %q : %q", s, note)
		}
	}
	if strings.Contains(note, "désactivée") {
		t.Errorf("règle désactivée résumée : %q", note)
	}
	if _, ok := res.Notes["api.example.com"]; ok {
		t.Errorf("note posée sur un hôte hors proxy")
	}
}

func TestBadToken(t *testing.T) {
	srv := fakeAPI(t)
	defer srv.Close()
	res, err := New(tokenFile(t, "wrong"), srv.URL).Scan(context.Background(), []string{"www.example.com", "x.example.org"})
	if err != nil {
		t.Fatalf("un refus n'est pas une erreur : %v", err)
	}
	got := byKey(res.Findings)
	if len(got) != 2 || !strings.Contains(got["cf.token.scope@example.com"].Evidence, "Zone Read") {
		t.Errorf("constats : %v", got)
	}
	if _, err := New(tokenFile(t, " \n"), srv.URL).Scan(context.Background(), nil); err == nil {
		t.Error("jeton vide accepté")
	}
	if _, err := New(filepath.Join(t.TempDir(), "absent"), srv.URL).Scan(context.Background(), nil); err == nil {
		t.Error("fichier de jeton absent accepté")
	}
}

func TestNoRulesAndRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/zones":
			ok(w, []map[string]string{{"id": "z", "name": "example.com"}}, 1, 1)
		case "/zones/z/dnssec":
			// Une redirection ne doit pas être suivie (le jeton partirait ailleurs).
			http.Redirect(w, r, "http://192.0.2.1/", http.StatusFound)
		default:
			fail(w, http.StatusNotFound, 7003, "not found")
		}
	}))
	defer srv.Close()
	res, err := New(tokenFile(t, token), srv.URL).Scan(context.Background(), []string{"example.com"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Errorf("redirection : %v", err)
	}
	if n := res.Notes["example.com"]; n != "Cloudflare : aucune règle de pare-feu personnalisée active" {
		t.Errorf("note : %q", n)
	}
}

func TestSummarize(t *testing.T) {
	cases := []struct{ action, expr, want string }{
		{"block", `ip.src.country in {"cn" "RU"}`, "pays bloqués CN, RU"},
		{"block", `ip.geoip.country ne "FR"`, "pays autorisés FR"},
		{"managed_challenge", `not ip.geoip.country eq "FR"`, "pays hors FR : managed_challenge"},
		{"block", `cf.verified_bot_category in {"AI Crawler"}`, "robots vérifiés bloqués"},
		{"block", `http.user_agent contains "x"`, `user agents "x" : block`},
		{"log", `true`, `règle "sans description" (log)`},
	}
	for _, c := range cases {
		desc := ""
		if c.action != "log" {
			desc = "d"
		}
		got := strings.Join(summarize(c.action, c.expr, desc), " ; ")
		if !strings.Contains(got, c.want) {
			t.Errorf("%s %s : %q sans %q", c.action, c.expr, got, c.want)
		}
	}
}

func TestGlobalKeyRefused(t *testing.T) {
	f := filepath.Join(t.TempDir(), "tok")
	key := strings.Repeat("a1", 18) + "b" // 37 caractères hexadécimaux
	os.WriteFile(f, []byte(key+"\n"), 0o600)
	_, err := New(f, "http://127.0.0.1:9").Scan(context.Background(), []string{"app.example.com"})
	if err == nil || !strings.Contains(err.Error(), "Global API Key") || strings.Contains(err.Error(), key) {
		t.Fatalf("clé globale : %v", err)
	}
	if IsGlobalKey(strings.Repeat("A", 40)) {
		t.Error("jeton API pris pour la clé globale")
	}
}

func TestCountries(t *testing.T) {
	a, b := countries(`(not ip.geoip.country in {"FR" "BE" "re"}) or (ip.src.country eq "CN")`)
	if strings.Join(a, ",") != "FR,BE,RE" || strings.Join(b, ",") != "CN" {
		t.Errorf("autorisés %v, bloqués %v", a, b)
	}
	g := cdnprov.Geo{Allowed: a, Blocked: b}
	if !g.Blocks("de") || g.Blocks("FR") || !g.Blocks("CN") {
		t.Error("Blocks")
	}
}
