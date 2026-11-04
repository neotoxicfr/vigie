package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/engine"
	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/source/manual"
	"github.com/neotoxicfr/vigie/internal/store"
)

type fakeRunner struct {
	started int
	host    string
}

func (f *fakeRunner) Start() (int64, error)             { f.started++; return 42, nil }
func (f *fakeRunner) StartHost(h string) (int64, error) { f.host = h; return 43, nil }
func (f *fakeRunner) Current() (int64, bool)            { return 0, false }
func (f *fakeRunner) Progress() engine.Progress         { return engine.Progress{} }

func setup(t *testing.T, a config.Auth) (*httptest.Server, *store.Store, *fakeRunner) {
	t.Helper()
	return setupWith(t, a, config.DefaultRuntime())
}

func setupWith(t *testing.T, a config.Auth, rt config.Runtime) (*httptest.Server, *store.Store, *fakeRunner) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fr := &fakeRunner{}
	live, err := settings.NewLive(context.Background(), st, rt)
	if err != nil {
		t.Fatal(err)
	}
	man := manual.New(st)
	s, err := New(Deps{Cfg: &config.Config{DataDir: dir, Auth: a}, Settings: live, Store: st, Manual: man, Runner: fr, Version: "test",
		Sources: func(config.Runtime) []source.Source { return []source.Source{man} }})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, st, fr
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func csrfFrom(t *testing.T, c *http.Client, u string, h http.Header) string {
	req, _ := http.NewRequest("GET", u, nil)
	for k, v := range h {
		req.Header[k] = v
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := csrfRe.FindSubmatch(b)
	if m == nil {
		t.Fatalf("pas de jeton CSRF sur %s (%d)", u, resp.StatusCode)
	}
	return string(m[1])
}

func TestBuiltinLogin(t *testing.T) {
	hash, err := HashPassword("bon-mot-de-passe")
	if err != nil {
		t.Fatal(err)
	}
	srv, _, fr := setup(t, config.Auth{Users: []config.User{{Name: "neo", PasswordHash: hash}}})
	c := client()

	resp, _ := c.Get(srv.URL + "/")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
		t.Fatalf("non connecté : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP : %q", csp)
	}
	tok := csrfFrom(t, c, srv.URL+"/login", nil)

	// Sans jeton CSRF : refus.
	resp, _ = c.PostForm(srv.URL+"/login", url.Values{"user": {"neo"}, "password": {"bon-mot-de-passe"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("login sans CSRF : %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(srv.URL+"/login", url.Values{"csrf": {tok}, "user": {"neo"}, "password": {"faux"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login?err=") {
		t.Errorf("mauvais mot de passe : %s", loc)
	}
	resp, _ = c.PostForm(srv.URL+"/login", url.Values{"csrf": {tok}, "user": {"neo"}, "password": {"bon-mot-de-passe"}})
	if resp.Header.Get("Location") != "/" {
		t.Fatalf("connexion : %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, p := range []string{"/", "/inventory"} {
		resp, _ = c.Get(srv.URL + p)
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 200 || !strings.Contains(string(b), "neo") {
			t.Errorf("%s connecté : %d", p, resp.StatusCode)
		}
	}

	tok = csrfFrom(t, c, srv.URL+"/", nil)
	// Jeton valide mais requête d'un autre site : refus.
	req, _ := http.NewRequest("POST", srv.URL+"/run", strings.NewReader("csrf="+tok))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, _ = c.Do(req); resp.StatusCode != http.StatusForbidden || fr.started != 0 {
		t.Errorf("POST inter-sites accepté : %d", resp.StatusCode)
	}
	resp, _ = c.PostForm(srv.URL+"/run", url.Values{"csrf": {tok}})
	if !strings.HasPrefix(resp.Header.Get("Location"), "/?ok=") || fr.started != 1 {
		t.Errorf("lancement : %s", resp.Header.Get("Location"))
	}

	// Cookie falsifié : refusé.
	c2 := client()
	u, _ := url.Parse(srv.URL)
	c2.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: "bmVv.abcdef"}})
	if resp, _ = c2.Get(srv.URL + "/"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("cookie falsifié accepté : %d", resp.StatusCode)
	}
}

func TestLockout(t *testing.T) {
	hash, _ := HashPassword("x")
	a := &auth{cfg: config.Auth{Users: []config.User{{Name: "neo", PasswordHash: hash}, {Name: "autre", PasswordHash: hash}}}, key: make([]byte, 32), fails: map[string]*failState{}}
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < maxFails; i++ {
		if ok, locked := a.login(ip, "neo", "faux"); ok || locked {
			t.Fatalf("essai %d : ok=%v locked=%v", i, ok, locked)
		}
	}
	if ok, locked := a.login(ip, "neo", "x"); ok || !locked {
		t.Error("le bon mot de passe passe pendant le blocage")
	}
	if ok, _ := a.login(netip.MustParseAddr("192.0.2.2"), "neo", "x"); !ok {
		t.Error("une autre IP est bloquée")
	}
	// Même IP (proxy partagé), autre utilisateur : pas de blocage collectif.
	if ok, _ := a.login(ip, "autre", "x"); !ok {
		t.Error("le blocage d'un utilisateur bloque les autres derrière la même IP")
	}
	// Essais parallèles : la limite tient, l'essai est compté avant la vérification.
	ip4 := netip.MustParseAddr("192.0.2.4")
	var wg sync.WaitGroup
	var tried atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, locked := a.login(ip4, "neo", "faux"); !locked {
				tried.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := tried.Load(); n > maxFails {
		t.Errorf("%d vérifications parallèles, limite %d", n, maxFails)
	}
	if ok, _ := a.login(netip.MustParseAddr("192.0.2.3"), "inconnu", "x"); ok {
		t.Error("utilisateur inconnu accepté")
	}
}

func TestProxyHeader(t *testing.T) {
	// httptest écoute sur 127.0.0.1 : déclaré de confiance dans un cas, pas dans l'autre.
	trusted, _, _ := setup(t, config.Auth{Proxy: &config.Proxy{Header: "Remote-User", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}})
	untrusted, _, _ := setup(t, config.Auth{Proxy: &config.Proxy{Header: "Remote-User", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}})
	get := func(base string, hdr bool) int {
		req, _ := http.NewRequest("GET", base+"/", nil)
		if hdr {
			req.Header.Set("Remote-User", "neo")
		}
		resp, err := client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	if c := get(trusted.URL, true); c != 200 {
		t.Errorf("proxy de confiance : %d", c)
	}
	if c := get(trusted.URL, false); c != http.StatusUnauthorized {
		t.Errorf("sans en-tête : %d", c)
	}
	if c := get(untrusted.URL, true); c != http.StatusUnauthorized {
		t.Errorf("en-tête d'une IP non déclarée accepté : %d", c)
	}
	if resp, _ := client().Get(trusted.URL + "/login"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("page de connexion en mode proxy : %d", resp.StatusCode)
	}
}

func TestPagesAndAccept(t *testing.T) {
	srv, st, fr := setup(t, config.Auth{Proxy: &config.Proxy{Header: "Remote-User", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}})
	ctx := context.Background()
	id, _ := st.BeginRun(ctx, time.Now())
	f := check.Finding{Check: "http.hsts.absent", Target: "app.example.com:443", Vantage: "public", Severity: check.Medium, Title: "HSTS absent", Evidence: "<script>alert(1)</script>"}
	f2 := f
	f2.Vantage = "origine"
	st.SaveFindings(ctx, id, []check.Finding{f, f2, {Check: "tls.cert.info", Target: "app.example.com:443", Vantage: "public", Title: "certificat"},
		{Check: "http.csp.no-script-src", Target: "b.example.com:443", Vantage: "public", Severity: check.Medium, Title: "CSP sans script-src"}})
	st.FinishRun(ctx, id, time.Now(), "ok", "")

	h := http.Header{"Remote-User": {"neo"}}
	do := func(method, path string, form url.Values) (*http.Response, string) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(form.Encode()))
		req.Header = h.Clone()
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	for _, p := range []string{"/", "/issues", "/problems", "/hosts", "/host/app.example.com", "/runs", "/inventory", "/settings"} {
		if resp, body := do("GET", p, nil); resp.StatusCode != 200 || !strings.Contains(body, "neo") {
			t.Errorf("%s : %d", p, resp.StatusCode)
		}
	}
	_, body := do("GET", "/issues", nil)
	if strings.Count(body, "HSTS absent") != 1 {
		t.Errorf("un écart vu de deux points de vue doit tenir sur une ligne (%d)", strings.Count(body, "HSTS absent"))
	}
	if !strings.Contains(body, "v-public") || !strings.Contains(body, "v-origine") {
		t.Error("pastilles de points de vue absentes")
	}
	if strings.Contains(body, "tls.cert.info") {
		t.Error("constat info affiché par défaut")
	}
	if _, body = do("GET", "/issues?sev=0", nil); !strings.Contains(body, "tls.cert.info") {
		t.Error("info absent avec la case info seule")
	}
	if _, body = do("GET", "/issues?sev=3", nil); strings.Contains(body, "HSTS absent") {
		t.Error("moyen affiché avec la seule case élevé")
	}
	key := f.IssueKey()
	_, body = do("GET", "/issue/"+key, nil)
	if !strings.Contains(body, "HSTS") || strings.Contains(body, "<script>alert") {
		t.Error("détail : contenu manquant ou non échappé")
	}
	if !strings.Contains(body, "Pourquoi c'est un risque") {
		t.Error("explication de la base de connaissance absente")
	}
	if resp, body := do("GET", "/issue/"+key+"?panel=1", nil); resp.StatusCode != 200 || strings.Contains(body, "<html") {
		t.Errorf("fragment du tiroir : %d, page entière=%v", resp.StatusCode, strings.Contains(body, "<html"))
	}
	if resp, _ := do("GET", "/issue/"+strings.Repeat("0", 32), nil); resp.StatusCode != 404 {
		t.Errorf("écart inconnu : %d", resp.StatusCode)
	}

	tok := csrfFrom(t, client(), srv.URL+"/", h)
	// Portée hôte : l'écart passe en « assumé », les autres restent.
	resp, _ := do("POST", "/accept", url.Values{"csrf": {tok}, "key": {key}, "scope": {"host"}, "note": {"voulu"}, "back": {"/issues"}})
	if !strings.Contains(resp.Header.Get("Location"), "ok=") {
		t.Fatalf("assumer : %s", resp.Header.Get("Location"))
	}
	if _, body = do("GET", "/issues", nil); strings.Contains(body, "HSTS absent") {
		t.Error("écart assumé encore dans les ouverts")
	}
	// Portée globale : le contrôle devient une exclusion, visible et réversible.
	do("POST", "/accept", url.Values{"csrf": {tok}, "check": {"http.csp.no-script-src"}, "scope": {"global"}, "note": {"choix"}, "back": {"/problems"}})
	if _, body = do("GET", "/settings", nil); !strings.Contains(body, "http.csp.no-script-src") {
		t.Error("exclusion absente des réglages")
	}
	if _, body = do("GET", "/issues", nil); strings.Contains(body, "CSP sans script-src") {
		t.Error("contrôle exclu encore ouvert")
	}
	do("POST", "/unaccept", url.Values{"csrf": {tok}, "check": {"http.csp.no-script-src"}, "back": {"/settings"}})
	if _, body = do("GET", "/issues", nil); !strings.Contains(body, "CSP sans script-src") {
		t.Error("contrôle réactivé toujours caché")
	}
	resp, _ = do("POST", "/accept", url.Values{"csrf": {tok}, "key": {key}, "note": {""}, "back": {"/issues"}})
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Error("assumer sans raison accepté")
	}
	resp, _ = do("POST", "/accept", url.Values{"csrf": {tok}, "key": {key}, "note": {"x"}, "back": {"https://evil.example"}})
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/?ok=") {
		t.Errorf("redirection ouverte : %s", loc)
	}
	do("POST", "/retest", url.Values{"csrf": {tok}, "host": {"App.Example.com"}, "back": {"/hosts"}})
	if fr.host != "app.example.com" {
		t.Errorf("re-test : %q", fr.host)
	}

	run, _ := st.GetRun(context.Background(), id)
	_, body = do("GET", "/runs/"+runRef(run.Started)+"/export.json", nil)
	if resp, _ := do("GET", "/runs/"+strconv.FormatInt(id, 10)+"/export.json", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("export par numéro : %d, attendu 404", resp.StatusCode)
	}
	var exp struct {
		Findings []struct {
			Issue    string
			Accepted *store.Acceptance
		}
	}
	if err := json.Unmarshal([]byte(body), &exp); err != nil || len(exp.Findings) != 4 {
		t.Fatalf("export : %v %s", err, body)
	}

	// Réglages : section validée, invalide refusée.
	resp, _ = do("POST", "/settings/vantages", url.Values{"csrf": {tok}, "resolver": {"1.1.1.1:53"}, "origin": {"203.0.113.7"}, "public_ips": {""}, "internal": {""}})
	if !strings.Contains(resp.Header.Get("Location"), "ok=") {
		t.Errorf("réglage valide refusé : %s", resp.Header.Get("Location"))
	}
	resp, _ = do("POST", "/settings/vantages", url.Values{"csrf": {tok}, "resolver": {"pas-une-ip"}, "origin": {""}})
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Error("résolveur invalide accepté")
	}
	resp, _ = do("POST", "/settings/scan", url.Values{"csrf": {tok}, "budget": {"100"}, "timeout": {"1h"}, "ports": {""}, "cadence": {"1s"}})
	if !strings.Contains(resp.Header.Get("Location"), "err=") {
		t.Error("cadence arbitraire acceptée")
	}

	resp, _ = do("POST", "/targets", url.Values{"csrf": {tok}, "host": {"Mail.Example.com"}, "ports": {"25, 993"}})
	if !strings.Contains(resp.Header.Get("Location"), "ok=") {
		t.Errorf("ajout de cible : %s", resp.Header.Get("Location"))
	}
	if _, body = do("GET", "/inventory", nil); !strings.Contains(body, "mail.example.com") {
		t.Error("cible absente de l'inventaire")
	}
}

func TestGrade(t *testing.T) {
	for _, c := range []struct {
		open [4]int
		want string
	}{{[4]int{}, "A"}, {[4]int{0, 3, 0, 0}, "A"}, {[4]int{0, 6, 0, 0}, "B"}, {[4]int{0, 0, 0, 1}, "C"}, {[4]int{0, 0, 3, 1}, "D"}, {[4]int{0, 0, 0, 4}, "F"}} {
		if g, _ := grade(c.open); g != c.want {
			t.Errorf("%v : %s, attendu %s", c.open, g, c.want)
		}
	}
}

func TestMarkdownEscapes(t *testing.T) {
	out := string(markdown("## Titre\n- **gras** et `code`\n\n<script>alert(1)</script>\n\n```\n<b>x</b>\n```\n\n" +
		"**Titre gras**\nsuite\n\n1. un\n2. deux\n\n| Cible | Écart |\n|:--|---|\n| a | b |\n\n[x](javascript:alert(1)) <img src=x onerror=alert(1)>"))
	for _, want := range []string{"<h4>Titre</h4>", "<li><strong>gras</strong> et <code>code</code></li>", "<pre><code>&lt;b&gt;x&lt;/b&gt;",
		"<ol>", "<table>", "<strong>Titre gras</strong><br>", `<th align="left">Cible</th>`, "<td>b</td>"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de %s", want, out)
		}
	}
	for _, bad := range []string{"<script>", "javascript:", "onerror", "style="} {
		if strings.Contains(out, bad) {
			t.Errorf("%q injecté : %s", bad, out)
		}
	}
}

func TestSafeBack(t *testing.T) {
	for in, want := range map[string]string{"/run/1": "/run/1", "//evil.example": "/", "/\t/evil.example": "/",
		"/\\evil": "/", "https://evil.example": "/", "/a\nb": "/", "/run/1?etat=assumé": "/run/1?etat=assumé"} {
		if got := safeBack(in); got != want {
			t.Errorf("safeBack(%q) = %q, attendu %q", in, got, want)
		}
	}
}

func TestFlashAndLogout(t *testing.T) {
	hash, _ := HashPassword("bon-mot-de-passe")
	srv, _, _ := setup(t, config.Auth{Users: []config.User{{Name: "neo", PasswordHash: hash}}})
	c := client()
	tok := csrfFrom(t, c, srv.URL+"/login", nil)
	resp, _ := c.PostForm(srv.URL+"/login", url.Values{"csrf": {tok}, "user": {"neo"}, "password": {"bon-mot-de-passe"}})
	if resp.Header.Get("Location") != "/" {
		t.Fatal("connexion")
	}
	u, _ := url.Parse(srv.URL)
	stolen := c.Jar.Cookies(u)

	// Message non signé : ignoré.
	resp, _ = c.Get(srv.URL + "/?err=vigie+a+migr%C3%A9+vers+evil.example")
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), `class="flash err"`) {
		t.Error("message forgé affiché")
	}

	tok = csrfFrom(t, c, srv.URL+"/", nil)
	resp, _ = c.PostForm(srv.URL+"/settings/scan", url.Values{"csrf": {tok}, "budget": {"20000"}, "timeout": {"2h"}, "cadence": {"24h"}})
	loc := resp.Header.Get("Location")
	resp, _ = c.Get(srv.URL + loc)
	b, _ = io.ReadAll(resp.Body)
	if !strings.Contains(string(b), "Réglages enregistrés") {
		t.Errorf("message signé absent (%s)", loc)
	}

	if resp, _ = c.PostForm(srv.URL+"/logout", url.Values{"csrf": {tok}}); resp.Header.Get("Location") != "/login" {
		t.Fatalf("déconnexion : %d", resp.StatusCode)
	}
	// Le cookie volé avant la déconnexion ne vaut plus rien.
	c2 := client()
	c2.Jar.SetCookies(u, stolen)
	if resp, _ = c2.Get(srv.URL + "/"); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("cookie d'avant la déconnexion accepté : %d", resp.StatusCode)
	}
}

// Le bouton d'analyse n'apparaît que si la clé du fournisseur est en place.
func TestAIButtonNeedsKey(t *testing.T) {
	srv, st, _ := setup(t, config.Auth{Proxy: &config.Proxy{Header: "Remote-User", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}})
	ctx := context.Background()
	id, _ := st.BeginRun(ctx, time.Now())
	st.FinishRun(ctx, id, time.Now(), "ok", "")
	h := http.Header{"Remote-User": {"neo"}}
	do := func(method, path string, form url.Values) string {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(form.Encode()))
		req.Header = h.Clone()
		if form != nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if strings.Contains(do("GET", "/", nil), "Analyser ce passage") {
		t.Error("bouton affiché sans fournisseur")
	}
	dir := t.TempDir()
	old := secretDir
	secretDir = dir + "/"
	t.Cleanup(func() { secretDir = old })
	key := filepath.Join(dir, "anthropic_api_key")
	os.WriteFile(key, nil, 0o600)
	tok := csrfFrom(t, client(), srv.URL+"/", h)
	do("POST", "/settings/ai", url.Values{"csrf": {tok}, "provider": {"anthropic"}, "key_file": {key}})
	if strings.Contains(do("GET", "/", nil), "Analyser ce passage") {
		t.Error("bouton affiché avec une clé vide")
	}
	os.WriteFile(key, []byte("sk-ant-api03-test"), 0o600)
	if !strings.Contains(do("GET", "/", nil), "Analyser ce passage") {
		t.Error("bouton absent alors que la clé est en place")
	}
}

func TestSecretPathRestricted(t *testing.T) {
	cases := []struct {
		in, old string
		ok      bool
	}{
		{"", "/x", true},
		{"/etc/old", "/etc/old", true}, // valeur du fichier de configuration, inchangée
		{"/run/secrets/cloudflare_api_token", "", true},
		{"/data/session.key", "", false},
		{"/run/secrets/../../data/session.key", "", false},
		{"/run/secrets/sub/x", "", false},
		{"/authelia/configuration.yml", "", false},
		{"relatif", "", false},
	}
	for _, c := range cases {
		if _, err := secretPath(c.in, c.old, "test"); (err == nil) != c.ok {
			t.Errorf("%q (ancien %q) : err=%v, ok attendu %v", c.in, c.old, err, c.ok)
		}
	}
}

// Résumé pour tableau de bord : jeton dédié, lecture seule, aucun nom d'hôte.
func TestSummaryAPI(t *testing.T) {
	proxy := config.Auth{Proxy: &config.Proxy{Header: "Remote-User", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}
	get := func(srv *httptest.Server, path, tok string) (int, string) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	srv, _, _ := setup(t, proxy)
	if code, body := get(srv, "/healthz", ""); code != 200 || body != "ok\n" {
		t.Errorf("healthz : %d %q", code, body)
	}
	if code, _ := get(srv, "/api/summary", strings.Repeat("x", 40)); code != http.StatusNotFound {
		t.Errorf("sans jeton configuré : %d, attendu 404", code)
	}

	tok := strings.Repeat("a1", 24)
	f := filepath.Join(t.TempDir(), "summary_token")
	os.WriteFile(f, []byte(tok+"\n"), 0o600)
	rt := config.DefaultRuntime()
	rt.API.TokenFile = f
	srv, st, _ := setupWith(t, proxy, rt)
	ctx := context.Background()
	id, _ := st.BeginRun(ctx, time.Now())
	st.SaveFindings(ctx, id, []check.Finding{{Check: "http.csp.absent", Target: "secret-host.example.com:443", Vantage: "public", Severity: check.Medium}})
	st.FinishRun(ctx, id, time.Now(), "ok", "")
	for _, bad := range []string{"", "faux", tok[:len(tok)-1] + "b"} {
		if code, _ := get(srv, "/api/summary", bad); code != http.StatusUnauthorized {
			t.Errorf("jeton %q : %d, attendu 401", bad, code)
		}
	}
	code, body := get(srv, "/api/summary", tok)
	var out struct {
		LastRun struct{ Status string } `json:"last_run"`
		Open    struct{ Total, Medium int }
		Hosts   struct{ Total int }
	}
	if err := json.Unmarshal([]byte(body), &out); code != 200 || err != nil || out.LastRun.Status != "ok" || out.Open.Medium != 1 || out.Hosts.Total != 1 {
		t.Errorf("résumé : %d %s", code, body)
	}
	if strings.Contains(body, "secret-host") || strings.Contains(body, "example.com") {
		t.Errorf("nom d'hôte dans le résumé : %s", body)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/summary", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if resp, err := http.DefaultClient.Do(req); err == nil && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST accepté : %d", resp.StatusCode)
	}
}
