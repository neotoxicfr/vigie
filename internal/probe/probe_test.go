package probe

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/quic-go/quic-go/http3"
)

var local = scan.Fixed("test", netip.MustParseAddr("127.0.0.1"))

func port(t *testing.T, addr string) int {
	_, ps, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(ps)
	return n
}

// serve lance un serveur TLS + h2 dont le certificat couvre example.com et
// l'ajoute aux racines de confiance.
func serve(t *testing.T, h http.Handler) (*httptest.Server, scan.Target) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	rootCAs = pool
	t.Cleanup(func() { rootCAs = nil })
	return srv, scan.Target{Host: "example.com", Port: port(t, srv.Listener.Addr().String()), TLS: true}
}

func run(t *testing.T, g *scan.Guard, tg scan.Target) map[string]check.Finding {
	t.Helper()
	if g == nil {
		g = scan.NewGuard(1000, 2, 0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out := map[string]check.Finding{}
	for _, f := range Check(ctx, g, local, tg) {
		if len(f.Evidence) > maxEvidence {
			t.Errorf("%s : preuve trop longue (%d)", f.Check, len(f.Evidence))
		}
		if f.Target != tg.String() || f.Vantage != "test" {
			t.Errorf("%s : cible ou point de vue inattendu %q %q", f.Check, f.Target, f.Vantage)
		}
		out[f.Check] = f
	}
	return out
}

func want(t *testing.T, got map[string]check.Finding, sev check.Severity, ids ...string) {
	t.Helper()
	for _, id := range ids {
		f, ok := got[id]
		if !ok {
			t.Errorf("constat %s manquant ; reçus : %v", id, keys(got))
		} else if f.Severity != sev {
			t.Errorf("%s : sévérité %v, attendu %v", id, f.Severity, sev)
		}
	}
}

func none(t *testing.T, got map[string]check.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if f, ok := got[id]; ok {
			t.Errorf("constat %s inattendu : %+v", id, f)
		}
	}
}

func keys(m map[string]check.Finding) []string {
	var k []string
	for id := range m {
		k = append(k, id)
	}
	return k
}

const spa = `<!doctype html><html><head><title>app</title></head><body><div id=app></div></body></html>`

func TestBareSPA(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, spa)
	}))
	g := scan.NewGuard(1000, 1, 0)
	got := run(t, g, tg)
	want(t, got, check.Medium, "http.hsts.absent", "http.csp.absent", "http.xfo.absent")
	want(t, got, check.Low, "http.nosniff.absent", "http.permissions.absent")
	want(t, got, check.Info, "http.alpn.h2", "http.referrer.absent", "http.coop.absent", "http.corp.absent", "http.securitytxt.absent")
	none(t, got, "http.tls.unverified", "http.leak.git", "http.leak.env", "http.robots", "http.method.trace", "http.unreachable")
	// Toutes les places du garde sont rendues.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	rel, err := g.Acquire(ctx, "example.com")
	if err != nil {
		t.Fatalf("place du garde non rendue : %v", err)
	}
	rel()
}

func TestUnverified(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rootCAs = nil
	got := run(t, nil, tg)
	want(t, got, check.Medium, "http.tls.unverified", "http.csp.absent")
}

func TestHardened(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "unsafe-url, strict-origin-when-cross-origin")
		h.Set("Permissions-Policy", "camera=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		switch r.URL.Path {
		case "/.well-known/security.txt":
			fmt.Fprint(w, "Contact: mailto:security@example.com\n")
		case "/":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	got := run(t, nil, tg)
	want(t, got, check.Info, "http.hsts.preload-ready")
	none(t, got, "http.hsts.absent", "http.hsts.short", "http.hsts.no-subdomains", "http.csp.absent", "http.csp.unsafe-inline",
		"http.csp.unsafe-eval", "http.csp.wildcard", "http.csp.no-frame-ancestors", "http.xfo.absent", "http.nosniff.absent",
		"http.referrer.absent", "http.referrer.unsafe", "http.permissions.absent", "http.coop.absent", "http.corp.absent",
		"http.securitytxt.absent", "http.cors.reflect-origin")
}

func TestWeakHeaders(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Strict-Transport-Security", "max-age=3600")
		h.Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'")
		h.Set("Referrer-Policy", "no-referrer-when-downgrade")
		h.Set("Server", "nginx/1.25.3")
		h.Set("X-Powered-By", "PHP/8.1.2")
		h.Set("Content-Type", "text/html")
		if r.URL.Path != "/" {
			w.WriteHeader(404)
			fmt.Fprint(w, "Traceback (most recent call last):\n  File \"/srv/app.py\"")
			return
		}
		fmt.Fprint(w, `<html><script src="https://cdn.example.net/x.js"></script><script src="/local.js"></script>
<link rel=stylesheet href="https://cdn.example.net/a.css" integrity="sha384-x"><img src="http://example.com/a.png"></html>`)
	}))
	got := run(t, nil, tg)
	want(t, got, check.Low, "http.hsts.short", "http.csp.unsafe-eval", "http.referrer.unsafe", "http.server.version", "http.sri.missing", "http.mixed-content")
	want(t, got, check.Medium, "http.csp.unsafe-inline", "http.csp.wildcard", "http.xfo.absent", "http.error.verbose")
	want(t, got, check.Info, "http.hsts.no-subdomains", "http.csp.no-frame-ancestors", "http.tech")
	if ev := got["http.sri.missing"].Evidence; strings.Contains(ev, "a.css") || !strings.Contains(ev, "x.js") {
		t.Errorf("SRI : %q", ev)
	}
	if ev := got["http.tech"].Evidence; !strings.Contains(ev, "PHP") {
		t.Errorf("technos : %q", ev)
	}
}

func TestCookies(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Add("Set-Cookie", "sessionid=s3cr3t; Path=/")
		h.Add("Set-Cookie", "__Host-pref=b; Secure; Path=/x; SameSite=Lax; HttpOnly")
		h.Add("Set-Cookie", "ok=1; Secure; HttpOnly; SameSite=Strict")
		h.Add("Set-Cookie", "track=1; Secure; HttpOnly; SameSite=None")
		h.Add("Set-Cookie", "gone=; Max-Age=0")
	}))
	got := run(t, nil, tg)
	want(t, got, check.Medium, "http.cookie.no-secure.sessionid", "http.cookie.no-httponly.sessionid", "http.cookie.prefix-invalid.__host-pref")
	want(t, got, check.Low, "http.cookie.no-samesite.sessionid", "http.cache.private-cacheable")
	want(t, got, check.Info, "http.cookie.samesite-none.track")
	none(t, got, "http.cookie.no-secure.ok", "http.cookie.no-httponly.ok", "http.cookie.no-samesite.ok", "http.cookie.no-secure.gone")
	for _, f := range got {
		if strings.Contains(f.Evidence, "s3cr3t") {
			t.Errorf("%s : la valeur du cookie fuit dans la preuve", f.Check)
		}
	}
}

func TestCORS(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
	}))
	got := run(t, nil, tg)
	want(t, got, check.High, "http.cors.reflect-origin", "http.cors.null-origin")
}

func TestLeaksAndMethods(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodTrace:
			w.Header().Set("Content-Type", "message/http")
			fmt.Fprintf(w, "TRACE / HTTP/1.1\r\nHost: %s\r\n", r.Host)
		case r.Method == http.MethodOptions:
			w.Header().Set("Allow", "GET, POST, PUT, DELETE")
		case r.URL.Path == "/.git/HEAD":
			fmt.Fprint(w, "ref: refs/heads/main\n")
		case r.URL.Path == "/.env":
			fmt.Fprint(w, "DB_PASSWORD=hunter2\nAPP_KEY=base64:zzz\n")
		case r.URL.Path == "/server-status":
			fmt.Fprint(w, "<html>Apache Server Status for example.com</html>")
		case r.URL.Path == "/robots.txt":
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin\n")
		case r.URL.Path == "/":
			fmt.Fprint(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	got := run(t, nil, tg)
	want(t, got, check.High, "http.leak.git", "http.leak.env")
	want(t, got, check.Medium, "http.leak.server-status", "http.method.trace")
	want(t, got, check.Info, "http.method.list", "http.robots", "http.securitytxt.absent")
	none(t, got, "http.leak.phpinfo", "http.leak.ds-store", "http.leak.server-info")
	if ev := got["http.leak.env"].Evidence; strings.Contains(ev, "hunter2") || !strings.Contains(ev, "DB_PASSWORD") {
		t.Errorf("preuve .env : %q", ev)
	}
}

// Une SPA qui renvoie le même 200 partout, même avec un contenu qui ressemble à une fuite.
func TestSPALookalike(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ref: refs/heads/main\nKEY_NAME=1\nContact: x\nDisallow: /a\n")
	}))
	got := run(t, nil, tg)
	none(t, got, "http.leak.git", "http.leak.env", "http.robots")
	want(t, got, check.Info, "http.securitytxt.absent")
}

func Test429Suspends(t *testing.T) {
	var n atomic.Int32
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	g := scan.NewGuard(1000, 2, 0)
	got := run(t, g, tg)
	if n.Load() != 1 {
		t.Errorf("%d requêtes après un 429, attendu 1", n.Load())
	}
	if _, ok := g.Suspended()["example.com"]; !ok {
		t.Error("hôte non suspendu")
	}
	if len(got) != 0 {
		t.Errorf("constats après 429 : %v", keys(got))
	}
}

func TestPlainHTTP(t *testing.T) {
	redirect := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/", http.StatusMovedPermanently)
	})
	for _, c := range []struct {
		name    string
		h       http.Handler
		missing bool
	}{{"redirige", redirect, false}, {"sert", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), true}} {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(c.h)
			defer srv.Close()
			tg := scan.Target{Host: "example.com", Port: port(t, srv.Listener.Addr().String())}
			httpPort = tg.Port
			defer func() { httpPort = 80 }()
			got := run(t, nil, tg)
			none(t, got, "http.hsts.absent")
			if c.missing {
				want(t, got, check.Medium, "http.redirect.https", "http.csp.absent")
			} else if len(got) != 0 {
				t.Errorf("redirection correcte : constats %v", keys(got))
			}
		})
	}
}

func TestRedirectChain(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r")); err == nil {
			http.Redirect(w, r, "/r"+strconv.Itoa(n+1), http.StatusFound)
			return
		}
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/r1", http.StatusFound)
		}
	}))
	got := run(t, nil, tg)
	want(t, got, check.Low, "http.redirect.chain-long")
	if !strings.Contains(got["http.redirect.chain-long"].Evidence, "6 sauts") {
		t.Errorf("preuve : %q", got["http.redirect.chain-long"].Evidence)
	}
}

func TestStreamsBehindAuth(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ws":
			if r.Header.Get("Upgrade") != "websocket" || r.Header.Get("Sec-Websocket-Key") == "" {
				w.WriteHeader(400)
				return
			}
			c, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			buf.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			buf.Flush()
			c.Close()
		case "/events":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			http.NewResponseController(w).Flush()
			<-r.Context().Done()
		default:
			http.Redirect(w, r, "https://auth.example.net/?rd=x", http.StatusFound)
		}
	}))
	tg.Paths = []string{"/ws", "/events"}
	tg.Route = &source.Route{Hosts: []string{"example.com"}}
	got := run(t, nil, tg)
	want(t, got, check.High, "http.ws.unprotected", "http.sse.unprotected")
	want(t, got, check.Info, "http.ws.open")
	none(t, got, "http.csp.absent") // page de redirection : pas de contrôle de contenu
	want(t, got, check.Medium, "http.hsts.absent")
}

func TestH3(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	srv, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=60`, port(t, pc.LocalAddr().String())))
	}))
	h3 := &http3.Server{Handler: h, TLSConfig: http3.ConfigureTLSConfig(srv.TLS.Clone())}
	go h3.Serve(pc)
	defer h3.Close()
	got := run(t, nil, tg)
	want(t, got, check.Info, "http.h3.advertised", "http.h3.ok")
	none(t, got, "http.h3.broken")

	h3.Close()
	pc.Close()
	got = run(t, nil, tg)
	want(t, got, check.Low, "http.h3.broken")
}

func TestHeaderEdgeCases(t *testing.T) {
	cases := []struct {
		name, hdr, val string
		id             string
		present        bool
	}{
		{"strict-dynamic de Google", "Content-Security-Policy", "script-src 'nonce-abc' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'", "http.csp.wildcard", false},
		{"https: seul reste large", "Content-Security-Policy", "script-src https: 'self'; object-src 'none'", "http.csp.wildcard", true},
		{"CSP frame-ancestors seule : pas wildcard", "Content-Security-Policy", "frame-ancestors 'self'", "http.csp.wildcard", false},
		{"CSP frame-ancestors seule : scripts non restreints", "Content-Security-Policy", "frame-ancestors 'self'", "http.csp.no-script-src", true},
		{"HSTS max-age=0", "Strict-Transport-Security", "max-age=0", "http.hsts.absent", true},
		{"port Alt-Svc hors plage", "Alt-Svc", `h3=":70000"; ma=60`, "http.h3.advertised", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(c.hdr, c.val)
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprint(w, spa)
			}))
			got := run(t, nil, tg)
			if _, ok := got[c.id]; ok != c.present {
				t.Errorf("%s : présent=%v, attendu %v", c.id, ok, c.present)
			}
			if c.hdr == "Strict-Transport-Security" && got[c.id].Evidence != "max-age=0" {
				t.Errorf("preuve %q", got[c.id].Evidence)
			}
		})
	}
}

// Page de blocage Cloudflare : un seul constat, aucun jugement des en-têtes.
func TestCDNBlockPage(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("Cf-Ray", "a4f0e4c66fc5e537-FRA")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<title>Attention Required! | Cloudflare</title><div id="cf-error-details">Sorry, you have been blocked</div>`)
	}))
	got := run(t, nil, tg)
	if _, ok := got["http.cdn-blocked"]; !ok || len(got) > 2 {
		t.Errorf("constats : %v", keys(got))
	}
	if _, ok := got["http.csp.absent"]; ok {
		t.Error("en-têtes de la page de blocage jugés")
	}
}

// connectProxy : proxy HTTP CONNECT minimal qui envoie tout vers backend.
func connectProxy(t *testing.T, backend string) *url.URL {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				if req, err := http.ReadRequest(br); err != nil || req.Method != http.MethodConnect {
					return
				}
				b, err := net.Dial("tcp", backend)
				if err != nil {
					return
				}
				defer b.Close()
				io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n")
				go io.Copy(b, br)
				io.Copy(c, b)
			}(c)
		}
	}()
	u, _ := url.Parse("http://" + ln.Addr().String())
	return u
}

// Depuis une sortie, un portail d'authentification ne donne que le constat
// d'accès : ses en-têtes ne sont pas ceux de l'application.
func TestExitSeesAuthOnly(t *testing.T) {
	srv, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized) // portail, sans CSP ni XFO
	}))
	v := scan.ProxyVantage("etranger", &scan.Proxy{URL: connectProxy(t, srv.Listener.Addr().String())})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got := map[string]bool{}
	for _, f := range Check(ctx, scan.NewGuard(1000, 2, 0), v, tg) {
		got[f.Check] = true
	}
	if !got["http.access.auth"] || got["http.csp.absent"] || got["http.xfo.absent"] {
		t.Errorf("constats : %v", got)
	}
}

// Réponse du contrôle d'accès (401 d'un forwardAuth, avec les en-têtes du proxy) :
// rien n'est jugé de la page, un seul constat le dit.
func TestAuthGateNotJudged(t *testing.T) {
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		http.SetCookie(w, &http.Cookie{Name: "portal", Value: "x"})
		w.WriteHeader(http.StatusUnauthorized)
	}))
	got := run(t, nil, tg)
	want(t, got, check.Info, "http.auth.session-required")
	none(t, got, "http.csp.no-script-src", "http.csp.absent", "http.xfo.absent", "http.cookie.no-secure.portal", "http.nosniff.absent")
}

// Portail audité lui aussi (dans le périmètre de la route) : le renvoi qui emporte
// l'adresse de départ n'est pas suivi, sa page n'est pas jugée pour la cible.
func TestInScopePortalNotFollowed(t *testing.T) {
	var portalHit bool
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "auth.example.com" || strings.HasPrefix(r.Host, "auth.example.com:") {
			portalHit = true
			w.Write([]byte(spa))
			return
		}
		http.Redirect(w, r, "https://auth.example.com/?rd=https%3A%2F%2Fexample.com%2F", http.StatusFound)
	}))
	tg.Route = &source.Route{Hosts: []string{"example.com", "auth.example.com"}}
	got := run(t, nil, tg)
	want(t, got, check.Info, "http.auth.session-required")
	none(t, got, "http.csp.absent", "http.xfo.absent")
	if portalHit {
		t.Error("page du portail suivie et jugée pour la cible")
	}
}

// Racine qui n'est pas une page (« OK » en texte) : pas de CSP, XFO ni
// Permissions-Policy exigés ; la page choisie, elle, est jugée.
func TestNonDocumentAndPage(t *testing.T) {
	var gotPath string
	_, tg := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/page.html" {
			gotPath = r.URL.RequestURI()
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(spa))
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("OK"))
	}))
	got := run(t, nil, tg)
	none(t, got, "http.csp.absent", "http.xfo.absent", "http.permissions.absent")
	want(t, got, check.Low, "http.nosniff.absent")

	tg.Page = "/app/page.html?v=1"
	got = run(t, nil, tg)
	want(t, got, check.Medium, "http.csp.absent", "http.xfo.absent")
	if gotPath != "/app/page.html?v=1" {
		t.Errorf("page demandée : %q", gotPath)
	}
}
