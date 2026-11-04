package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

func sample() (store.Run, []store.Delta, []source.Route) {
	run := store.Run{ID: 7, Started: time.Unix(1_800_000_000, 0), Status: "ok"}
	routes := []source.Route{{Name: "app@docker", Source: "traefik/nas", Hosts: []string{"app.example.com"}, Ports: []int{443},
		Middlewares: []source.Middleware{{Name: "auth@file", Kind: source.ForwardAuth}}}}
	ds := []store.Delta{
		{Finding: check.Finding{Check: "http.hsts.absent", Target: "app.example.com:443", Vantage: "dns", Severity: check.Medium,
			Title: "HSTS absent", Evidence: "origine 203.0.113.7, voir www.example.com et 2001:db8::5"}, State: store.New},
		{Finding: check.Finding{Check: "tls.cert.info", Target: "app.example.com:443", Vantage: "dns", Title: "info"}, State: store.Unchanged},
		{Finding: check.Finding{Check: "http.csp.absent", Target: "app.example.com:443", Vantage: "dns", Severity: check.Medium, Privileged: true},
			State: store.Unchanged, Accepted: &store.Acceptance{Note: "CSP de l'appli"}},
	}
	return run, ds, routes
}

func TestBuildMask(t *testing.T) {
	run, ds, routes := sample()
	clear, _ := Build(Input{Run: run, Deltas: ds, Routes: routes})
	if !strings.Contains(clear, "app.example.com") || strings.Contains(clear, "tls.cert.info") {
		t.Errorf("demande en clair : %s", clear)
	}
	if !strings.Contains(clear, "[http.csp.absent] app.example.com:443 — raison : CSP de l'appli") {
		t.Error("assumé absent de sa section")
	}
	masked, unmask := Build(Input{Run: run, Deltas: ds, Routes: routes, Mask: true})
	for _, leak := range []string{"example.com", "203.0.113.7", "2001:db8::5"} {
		if strings.Contains(masked, leak) {
			t.Errorf("%q fuit dans la demande masquée :\n%s", leak, masked)
		}
	}
	// La réponse du modèle reprend les jetons : ils redeviennent les vrais noms.
	tok := ""
	for _, f := range strings.Fields(masked) {
		if strings.HasPrefix(f, "host-") {
			tok = strings.Trim(f, ":,()")
			break
		}
	}
	if got := unmask("Corrige " + tok + " et ip-999."); !strings.Contains(got, "example.com") || !strings.Contains(got, "ip-999") {
		t.Errorf("rétablissement : %q (jeton %q)", got, tok)
	}
}

func TestMaskGaps(t *testing.T) {
	run, ds, routes := sample()
	routes[0].Hosts = []string{"Cloud.Example.com"}
	routes[0].Middlewares = append(routes[0].Middlewares, source.Middleware{Name: "headers.api@file"})
	ds = append(ds, store.Delta{Finding: check.Finding{Check: "tls.cert.lint.w_x", Target: "cloud.example.com:443", Vantage: "dns",
		Severity: check.Low, Title: "lint", Evidence: "SAN perso.example.net, admin.secret.example.com, ::1, ::ffff:192.0.2.9, fe80::1%x, CLOUD.EXAMPLE.COM."}},
		store.Delta{Finding: check.Finding{Check: "tls.cert.info", Target: "cloud.example.com:443", Vantage: "dns", Severity: check.Low, Title: "i"}})
	masked, unmask := Build(Input{Run: run, Deltas: ds, Routes: routes, Mask: true})
	for _, leak := range []string{"xample", "::1", "192.0.2.9", "perso", "secret", "fe80"} {
		if strings.Contains(strings.ToLower(masked), leak) {
			t.Errorf("%q fuit :\n%s", leak, masked)
		}
	}
	for _, keep := range []string{"http.hsts.absent", "tls.cert.lint.w_x", "tls.cert.info", "auth@file", "headers.api@file", "app@docker"} {
		if !strings.Contains(masked, keep) {
			t.Errorf("%q altéré :\n%s", keep, masked)
		}
	}
	// Même nom, casse différente : même jeton ; le rétablissement redonne le nom.
	if strings.Count(masked, "host-002") < 3 {
		t.Errorf("jeton non stable (%d) :\n%s", strings.Count(masked, "host-002"), masked)
	}
	if got := unmask("admin.secret.example.com"); got != "admin.secret.example.com" {
		t.Errorf("texte clair altéré : %q", got)
	}
	tok := regexp.MustCompile(`host-\d{3}`).FindAllString(masked, -1)
	if got := unmask(tok[len(tok)-1]); !strings.Contains(got, ".") {
		t.Errorf("rétablissement : %q", got)
	}
}

func TestOpenAI(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" || r.Header.Get("Authorization") != "Bearer k" {
			http.Error(w, "mauvaise requête", 400)
			return
		}
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"choices":[{"message":{"content":"## Synthèse\nRAS"},"finish_reason":"stop"}]}`)
	}))
	defer srv.Close()
	key := filepath.Join(t.TempDir(), "k")
	os.WriteFile(key, []byte("k\n"), 0o600)
	p, err := New(Config{Provider: "openai", BaseURL: srv.URL + "/v1/", Model: "llama", APIKeyFile: key})
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.Analyze(context.Background(), "sys", "demande")
	if err != nil || !strings.Contains(out, "RAS") {
		t.Fatalf("%q %v", out, err)
	}
	if got["model"] != "llama" || p.Name() != "openai/llama" {
		t.Errorf("corps : %v", got)
	}
}

func TestAnthropicRequest(t *testing.T) {
	var body map[string]any
	var beta string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		beta = r.Header.Get("anthropic-beta")
		json.NewDecoder(r.Body).Decode(&body)
		sse(w, "end_turn", "## Synthèse\nOK")
	}))
	defer srv.Close()
	p := newAnthropic("k", DefaultAnthropicModel, srv.URL)
	out, err := p.Analyze(context.Background(), "sys", "demande")
	if err != nil || !strings.Contains(out, "OK") {
		t.Fatalf("%q %v", out, err)
	}
	if body["stream"] != true || body["max_tokens"].(float64) < 32000 {
		t.Errorf("flux %v, max_tokens %v : un long rapport serait tronqué", body["stream"], body["max_tokens"])
	}
	if body["model"] != "claude-opus-5-5" || body["fallbacks"] != "default" || !strings.Contains(beta, "server-side-fallback-2026-07-01") {
		t.Errorf("requête : model=%v fallbacks=%v beta=%q", body["model"], body["fallbacks"], beta)
	}
	if oc, _ := body["output_config"].(map[string]any); oc["effort"] != "high" {
		t.Errorf("effort : %v", body["output_config"])
	}
	if _, has := body["thinking"]; has {
		t.Error("thinking envoyé : Opus 5.5 le refuse s'il n'est pas adaptatif")
	}
}

func TestAnthropicRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sse(w, "refusal", "")
	}))
	defer srv.Close()
	if _, err := newAnthropic("k", "claude-haiku-5-5", srv.URL).Analyze(context.Background(), "s", "p"); err == nil || !strings.Contains(err.Error(), "refusé") {
		t.Errorf("refus non signalé : %v", err)
	}
}

func TestConfigValidate(t *testing.T) {
	for _, c := range []struct {
		cfg Config
		ok  bool
	}{
		{Config{}, true},
		{Config{Provider: "anthropic"}, false},
		{Config{Provider: "anthropic", APIKeyFile: "/k"}, true},
		{Config{Provider: "openai", BaseURL: "http://x"}, false},
		{Config{Provider: "mistral"}, false},
	} {
		if err := c.cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("%+v : %v", c.cfg, err)
		}
	}
}

// sse répond comme l'API en flux : début, texte éventuel, fin avec stop_reason.
func sse(w http.ResponseWriter, stop, text string) {
	w.Header().Set("Content-Type", "text/event-stream")
	ev := func(name, data string) { fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data) }
	ev("message_start", `{"type":"message_start","message":{"id":"m","type":"message","role":"assistant","model":"x","content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":0}}}`)
	if text != "" {
		t, _ := json.Marshal(text)
		ev("content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		ev("content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+string(t)+`}}`)
		ev("content_block_stop", `{"type":"content_block_stop","index":0}`)
	}
	ev("message_delta", `{"type":"message_delta","delta":{"stop_reason":"`+stop+`"},"usage":{"output_tokens":5}}`)
	ev("message_stop", `{"type":"message_stop"}`)
}

func TestPromptFirstRunAndInfo(t *testing.T) {
	ds := []store.Delta{
		{Finding: check.Finding{Check: "port.open", Target: "198.51.100.7:443", Vantage: "vpn"}, State: store.New},
		{Finding: check.Finding{Check: "http.server.version", Target: "a.example.com:443", Vantage: "public"}, State: store.New},
	}
	p, _ := Build(Input{Run: store.Run{Started: time.Now(), Status: "ok"}, First: true, Decided: "Traefik remplace la CSP de l'application.", Deltas: ds})
	if !strings.Contains(p, "Choix déjà tranchés") || !strings.Contains(p, "Traefik remplace") ||
		!strings.Contains(p, "Premier passage") || !strings.Contains(p, "port.open") || strings.Contains(p, "http.server.version") {
		t.Errorf("demande :\n%s", p)
	}
}

// Assumés et exclus : hors des écarts ouverts, regroupés avec leur raison ;
// un même écart vu de trois points de vue tient sur une ligne.
func TestPromptSections(t *testing.T) {
	acc := &store.Acceptance{Note: "TestCookie sans secret"}
	ds := []store.Delta{
		{Finding: check.Finding{Check: "http.csp.absent", Target: "a.example.com:443", Vantage: "public", Severity: check.Medium, Privileged: true}, State: store.New},
		{Finding: check.Finding{Check: "http.csp.absent", Target: "a.example.com:443", Vantage: "vpn", Severity: check.Medium, Evidence: "vu de dehors"}, State: store.Unchanged},
		{Finding: check.Finding{Check: "http.csp.absent", Target: "a.example.com:443", Vantage: "origine", Severity: check.Low, Privileged: true}, State: store.Unchanged},
		{Finding: check.Finding{Check: "http.cookie.no-httponly.TestCookie", Target: "j.example.com:443", Vantage: "public", Severity: check.Medium}, State: store.Unchanged, Accepted: acc},
		{Finding: check.Finding{Check: "http.cookie.no-httponly.TestCookie", Target: "j.example.com:443", Vantage: "vpn", Severity: check.Medium}, State: store.Unchanged, Accepted: acc},
		{Finding: check.Finding{Check: "http.xfo.absent", Target: "old.example.com:443", Vantage: "public", Severity: check.Medium}, State: store.Resolved},
		{Finding: check.Finding{Check: "http.permissions.absent", Target: "b.example.com:443", Vantage: "public", Severity: check.Low, Title: "PP absent"}, State: store.Unchanged},
		{Finding: check.Finding{Check: "http.permissions.absent", Target: "c.example.com:443", Vantage: "public", Severity: check.Low, Title: "PP absent"}, State: store.Unchanged},
	}
	p, _ := Build(Input{Run: store.Run{Started: time.Now(), Status: "ok"}, Deltas: ds,
		Excluded: map[string]string{"tls.cipher.cbc-sha1": "restreindre est payant"}})
	open := p[strings.Index(p, "## Écarts ouverts"):strings.Index(p, "## Faits mesurés")]
	if strings.Count(open, "http.csp.absent") != 1 || !strings.Contains(open, "vues public, vpn, origine") || !strings.Contains(open, "état nouveau") ||
		!strings.Contains(open, "preuve : vu de dehors") || strings.Contains(open, "seulement depuis") {
		t.Errorf("écarts ouverts :\n%s", open)
	}
	if !strings.Contains(open, "[http.permissions.absent] 2 cibles : b.example.com:443, c.example.com:443") {
		t.Errorf("écarts identiques non regroupés :\n%s", open)
	}
	if strings.Contains(open, "TestCookie") || strings.Contains(open, "old.example.com") {
		t.Errorf("assumé ou résolu mêlé aux écarts ouverts :\n%s", open)
	}
	acc2 := p[strings.Index(p, "## Écarts assumés"):]
	if strings.Count(acc2, "[http.cookie.no-httponly.TestCookie]") != 1 || !strings.Contains(acc2, "raison : TestCookie sans secret") ||
		!strings.Contains(acc2, "[tls.cipher.cbc-sha1] — raison : restreindre est payant") {
		t.Errorf("assumés et exclus :\n%s", acc2)
	}
}
