package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/store"
)

type fakeRunner struct{ started int }

func (f *fakeRunner) Start() (int64, error)  { f.started++; return 9, nil }
func (f *fakeRunner) Current() (int64, bool) { return 0, false }

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

const token = "0123456789abcdef0123456789abcdef" // valeur factice de test gitleaks:allow

func TestMCP(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _ := st.BeginRun(ctx, time.Now())
	st.SaveFindings(ctx, id, []check.Finding{
		{Check: "http.hsts.absent", Target: "app.example.com:443", Vantage: "dns", Severity: check.Medium, Title: "HSTS absent"},
		{Check: "tls.cert.info", Target: "app.example.com:443", Vantage: "dns", Title: "certificat"},
	})
	st.SetInventory(ctx, id, []byte(`[{"name":"app@docker","source":"traefik/t","hosts":["app.example.com"],"tls":true,"middlewares":[{"name":"x","type":"plugin","kind":"other","config":{"secret":"ne pas exposer"}}]}]`))
	st.FinishRun(ctx, id, time.Now(), "ok", "")
	fr := &fakeRunner{}
	srv := httptest.NewServer(Handler(st, fr, "test", func() string { return token }))
	defer srv.Close()

	// Sans jeton : refus.
	resp, _ := http.Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sans jeton : %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
	if resp, _ = http.DefaultClient.Do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("mauvais jeton : %d", resp.StatusCode)
	}

	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil)
	cs, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: &http.Client{Transport: bearer{token}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	tools, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
		if strings.Contains(tl.Name, "accept") {
			t.Errorf("outil d'écriture sur le tri exposé : %s", tl.Name)
		}
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "vigie_analysis,vigie_findings,vigie_inventory,vigie_list_runs,vigie_start_run" {
		t.Errorf("outils : %v", names)
	}

	call := func(name string, args any, out any) {
		t.Helper()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		if res.IsError {
			t.Fatalf("%s : erreur %+v", name, res.Content)
		}
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, out)
	}
	var fo findingsOut
	call("vigie_findings", map[string]any{}, &fo)
	if fo.Total != 1 || fo.Findings[0].Check != "http.hsts.absent" || fo.Findings[0].Severity != "moyen" || fo.Findings[0].State != "nouveau" {
		t.Errorf("constats ouverts : %+v", fo)
	}
	call("vigie_findings", map[string]any{"state": "tout", "min_severity": 0}, &fo)
	if fo.Total != 2 {
		t.Errorf("tout : %d", fo.Total)
	}
	var inv inventoryOut
	call("vigie_inventory", map[string]any{"run_id": id}, &inv)
	if len(inv.Routes) != 1 || inv.Routes[0].Middlewares[0].Config != nil {
		t.Errorf("inventaire : %+v", inv)
	}
	var so startOut
	call("vigie_start_run", map[string]any{}, &so)
	if so.RunID != 9 || fr.started != 1 {
		t.Errorf("lancement : %+v", so)
	}
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "vigie_findings", Arguments: map[string]any{"run_id": 999}})
	if err == nil && !res.IsError {
		t.Error("passage inconnu sans erreur")
	}
}

func TestLoadToken(t *testing.T) {
	dir := t.TempDir()
	short := filepath.Join(dir, "s")
	writeFile(t, short, "court")
	if _, err := LoadToken(short); err == nil {
		t.Error("jeton court accepté")
	}
	good := filepath.Join(dir, "g")
	writeFile(t, good, token+"\n")
	if tok, err := LoadToken(good); err != nil || tok != token {
		t.Errorf("%q %v", tok, err)
	}
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDisabledWithoutToken(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "v.db"))
	defer st.Close()
	srv := httptest.NewServer(Handler(st, &fakeRunner{}, "test", func() string { return "" }))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer ")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != http.StatusNotFound {
		t.Errorf("MCP sans jeton configuré : %d", resp.StatusCode)
	}
}
