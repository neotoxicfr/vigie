package traefik

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/neotoxicfr/vigie/internal/source"
)

// fakeAPI sert les fixtures par pages de 3, comme l'API (X-Next-Page = 1 en fin).
func fakeAPI(t *testing.T, user, pass string) *httptest.Server {
	files := map[string]string{"/api/http/routers": "routers.json", "/api/http/middlewares": "middlewares.json",
		"/api/http/services": "services.json", "/api/entrypoints": "entrypoints.json"}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); user != "" && (u != user || p != pass) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f, ok := files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		var items []json.RawMessage
		json.Unmarshal(b, &items)
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		start, end := (page-1)*3, page*3
		if start >= len(items) && start > 0 {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		next := 1
		if end < len(items) {
			next = page + 1
		} else {
			end = len(items)
		}
		w.Header().Set("X-Next-Page", strconv.Itoa(next))
		json.NewEncoder(w).Encode(items[start:end])
	}))
}

func names(ms []source.Middleware) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Name)
	}
	return out
}

func TestDiscover(t *testing.T) {
	srv := fakeAPI(t, "", "")
	defer srv.Close()
	routes, err := New("test", srv.URL+"/", "", "").Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]source.Route{}
	for _, r := range routes {
		by[r.Name] = r
	}
	if _, ok := by["ping@internal"]; ok {
		t.Error("routeur internal gardé")
	}
	if _, ok := by["off@docker"]; ok {
		t.Error("routeur désactivé gardé")
	}
	if len(routes) != 6 {
		t.Fatalf("%d routes, attendu 6", len(routes))
	}

	app := by["app@docker"]
	if app.Source != "traefik/test" || !app.TLS || !reflect.DeepEqual(app.Ports, []int{443}) {
		t.Errorf("app : %+v", app)
	}
	if got, want := names(app.Middlewares), []string{"crowdsec@file", "sec-headers@file", "ipallow@file", "auth@file"}; !reflect.DeepEqual(got, want) {
		t.Errorf("chaîne déroulée : %v, attendu %v", got, want)
	}
	if got, want := app.Declared, []string{"crowdsec@file", "admin-chain@file"}; !reflect.DeepEqual(got, want) {
		t.Errorf("déclarés : %v", got)
	}
	if !reflect.DeepEqual(app.Backends, []string{"http://10.0.0.5:80"}) {
		t.Errorf("backends : %v", app.Backends)
	}
	ip := app.Middlewares[2]
	if ip.Kind != source.IPAllow || len(ip.AllowFrom) != 3 || ip.AllowFrom[2].String() != "198.51.100.7/32" {
		t.Errorf("allowlist : %+v", ip)
	}
	if a := app.Middlewares[3]; a.Kind != source.ForwardAuth || a.AuthURL != "http://auth:9091/api/authz/forward-auth" {
		t.Errorf("forwardAuth : %+v", a)
	}
	if string(app.Middlewares[0].Config) == "" {
		t.Error("config brute du plugin perdue")
	}

	site := by["site@docker"]
	if !reflect.DeepEqual(site.Hosts, []string{"example.com", "www.example.com"}) {
		t.Errorf("hôtes multiples : %v", site.Hosts)
	}
	if got := names(site.Middlewares); got[len(got)-1] != "www@docker" || site.Middlewares[len(got)-1].Kind != source.Redirect {
		t.Errorf("middleware non qualifié : %v", got)
	}

	if push := by["push@docker"]; !reflect.DeepEqual(push.Paths, []string{"/push"}) {
		t.Errorf("chemins : %v", push.Paths)
	}

	// v2 : le routeur ne liste pas les middlewares d'entrypoint, on les ajoute.
	leg := by["legacy@file"]
	if !reflect.DeepEqual(leg.Hosts, []string{"a.example.com", "b.example.com"}) ||
		!reflect.DeepEqual(leg.Ports, []int{80, 443}) ||
		!reflect.DeepEqual(names(leg.Middlewares), []string{"crowdsec@file"}) ||
		len(leg.Backends) != 2 {
		t.Errorf("legacy : %+v", leg)
	}

	if w := by["wild@docker"]; len(w.Hosts) != 0 || len(w.Problems) != 1 {
		t.Errorf("HostRegexp : %+v", w)
	}

	probs := strings.Join(by["broken@docker"].Problems, " | ")
	for _, want := range []string{"entrypoint ghost introuvable", "middleware missing@file introuvable", "chaîne cyclique"} {
		if !strings.Contains(probs, want) {
			t.Errorf("problème %q absent : %s", want, probs)
		}
	}
}

func TestBasicAuth(t *testing.T) {
	srv := fakeAPI(t, "vigie", "s3cret")
	defer srv.Close()
	pw := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(pw, []byte("s3cret\n"), 0o600)
	if _, err := New("t", srv.URL, "vigie", pw).Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := New("t", srv.URL, "vigie", "/nonexistent").Discover(context.Background()); err == nil {
		t.Fatal("fichier de mot de passe absent accepté")
	}
	_, err := New("t", srv.URL, "", "").Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("attendu 401, reçu %v", err)
	}
}

// Une API hostile qui annonce toujours une page suivante ne doit pas boucler.
func TestEndlessPages(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		w.Write([]byte("[]"))
	}))
	defer srv.Close()
	_, err := New("t", srv.URL, "", "").Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "pages") || hits > maxPages {
		t.Fatalf("hits=%d err=%v", hits, err)
	}
}

func TestCumulativeSize(t *testing.T) {
	chunk := []byte("[\"" + strings.Repeat("x", 5<<20) + "\"]")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		w.Write(chunk)
	}))
	defer srv.Close()
	_, err := New("t", srv.URL, "", "").Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "cumulées") {
		t.Fatalf("err=%v", err)
	}
}
