package engine

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/cdnprov"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/policy"
	"github.com/neotoxicfr/vigie/internal/scan"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/source/manual"
	"github.com/neotoxicfr/vigie/internal/store"
)

type failing struct{}

func (failing) Name() string { return "panne" }
func (failing) Discover(context.Context) ([]source.Route, error) {
	return nil, context.DeadlineExceeded
}

// Passage complet contre un serveur TLS local, saisi comme cible manuelle :
// constats enregistrés, inventaire gardé, source en panne → « partial ».
func TestRunEndToEnd(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	man := manual.New(st)
	if _, err := man.Add(context.Background(), "127.0.0.1", []int{port}, ""); err != nil {
		t.Fatal(err)
	}
	rt := config.Runtime{Scan: config.Scan{Budget: 500, Timeout: "1m", Ports: []int{port}}}
	e := New(context.Background(), func() config.Runtime { return rt }, st, srcs(man, failing{}))

	id, err := e.RunSync()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Start(); err != nil {
		t.Fatalf("relance après fin : %v", err)
	}
	for _, running := e.Current(); running; _, running = e.Current() {
		time.Sleep(50 * time.Millisecond)
	}

	r, err := st.GetRun(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != "partial" || r.Note == "" {
		t.Errorf("statut %q note %q, attendu partial avec la panne de source", r.Status, r.Note)
	}
	ds, _ := st.Compare(context.Background(), id)
	checks := map[string]bool{}
	for _, d := range ds {
		checks[d.Check] = true
	}
	for _, want := range []string{"http.hsts.absent", "http.server.version", "tls.cert.untrusted"} {
		if !checks[want] {
			t.Errorf("constat %s absent ; reçus : %v", want, checks)
		}
	}
	if inv, _ := st.Inventory(context.Background(), id); len(inv) < 10 {
		t.Errorf("inventaire vide : %s", inv)
	}
}

func TestStartTwice(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "v.db"))
	defer st.Close()
	block := make(chan struct{})
	e := New(context.Background(), func() config.Runtime { return config.Runtime{Scan: config.Scan{Budget: 10, Timeout: "1m"}} }, st,
		srcs(blocking{block}))
	if _, err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Start(); err != ErrRunning {
		t.Errorf("second départ : %v, attendu ErrRunning", err)
	}
	close(block)
	for _, running := e.Current(); running; _, running = e.Current() {
		time.Sleep(20 * time.Millisecond)
	}
}

type blocking struct{ c chan struct{} }

func (blocking) Name() string { return "lente" }
func (b blocking) Discover(context.Context) ([]source.Route, error) {
	<-b.c
	return nil, nil
}

type fixed []source.Route

func (fixed) Name() string                                       { return "fixe" }
func (f fixed) Discover(context.Context) ([]source.Route, error) { return f, nil }

// Une allowlist en /32 sur l'IP même de vigie rend la mesure privilégiée ; et
// une adresse publique non déclarée n'est jamais scannée en ports.
func TestPrivilegedAndPortScope(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	st, _ := store.Open(filepath.Join(t.TempDir(), "v.db"))
	defer st.Close()
	route := source.Route{Source: "fixe", Name: "app", Hosts: []string{"127.0.0.1"}, Ports: []int{port}, TLS: true,
		Middlewares: []source.Middleware{{Name: "allow", Kind: source.IPAllow, AllowFrom: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}}
	rt := config.Runtime{Scan: config.Scan{Budget: 500, Timeout: "1m", Ports: []int{port}}}
	e := New(context.Background(), func() config.Runtime { return rt }, st, srcs(fixed{route}))
	id, err := e.RunSync()
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := st.Compare(context.Background(), id)
	measured := 0
	for _, d := range ds {
		if d.Vantage == "public" && d.Check != "parity.no-route" {
			measured++
			if !d.Privileged {
				t.Errorf("%s non marqué privilégié", d.Check)
			}
		}
	}
	if measured == 0 {
		t.Fatal("aucune mesure")
	}
	isLocal := func(a netip.Addr) bool { return a.IsLoopback() }
	got := portTargets(context.Background(), []netip.Addr{netip.MustParseAddr("192.0.2.1")}, []string{"localhost"}, isLocal)
	for _, a := range got {
		if !a.IsLoopback() && a != netip.MustParseAddr("192.0.2.1") {
			t.Errorf("adresse non déclarée scannée : %s", a)
		}
	}
}

func srcs(s ...source.Source) func(config.Runtime) []source.Source {
	return func(config.Runtime) []source.Source { return s }
}

// Re-test d'un hôte : les autres gardent leurs constats (repris), rien n'est « résolu ».
func TestStartHostKeepsOthers(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "v.db"))
	defer st.Close()
	ctx := context.Background()
	old, _ := st.BeginRun(ctx, time.Now())
	st.SaveFindings(ctx, old, []check.Finding{{Check: "http.hsts.absent", Target: "autre.example.com:443", Vantage: "public", Severity: check.Medium}})
	st.FinishRun(ctx, old, time.Now(), "ok", "")
	rt := config.Runtime{Scan: config.Scan{Budget: 50, Timeout: "1m"}}
	e := New(ctx, func() config.Runtime { return rt }, st, srcs(fixed{{Source: "fixe", Name: "x", Hosts: []string{"127.0.0.1"}, Ports: []int{1}}}))
	id, err := e.StartHost("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	for _, running := e.Current(); running; _, running = e.Current() {
		time.Sleep(20 * time.Millisecond)
	}
	ds, _ := st.Compare(ctx, id)
	for _, d := range ds {
		if d.Target == "autre.example.com:443" && (d.State != store.Unchanged || !d.Carried) {
			t.Errorf("hôte non re-testé : %s carried=%v", d.State, d.Carried)
		}
	}
	if r, _ := st.GetRun(ctx, id); r.Scope != "127.0.0.1" {
		t.Errorf("portée : %q", r.Scope)
	}
}

func TestParseTrace(t *testing.T) {
	ip, loc := parseTrace(strings.NewReader("fl=1\nh=example.com\nip=203.0.113.9\nts=1\nloc=RE\nwarp=off\n"))
	if ip.String() != "203.0.113.9" || loc != "RE" {
		t.Errorf("%s %s", ip, loc)
	}
	if ip, _ := parseTrace(strings.NewReader("<html>")); ip.IsValid() {
		t.Error("ip inventée")
	}
}

func TestClassifyGeo(t *testing.T) {
	views := []exitView{{v: scan.ProxyVantage("vpn", nil), loc: "DE"}, {v: scan.ProxyVantage("fr", nil), loc: "FR"}}
	geo := map[string]cdnprov.Geo{"a.example.com": {Allowed: []string{"FR", "BE"}}, "b.example.com": {Allowed: []string{"FR"}}}
	in := []check.Finding{
		{Check: "http.cdn-blocked", Target: "a.example.com:443", Vantage: "vpn"},
		{Check: "http.hsts.absent", Target: "b.example.com:443", Vantage: "vpn", Severity: check.Medium}, // DE passe : contournement
		{Check: "http.cdn-blocked", Target: "a.example.com:443", Vantage: "fr"},                          // FR bloqué : inattendu
		{Check: "http.cdn-blocked", Target: "c.example.com:443", Vantage: "vpn"},                         // règles inconnues
		{Check: "http.hsts.absent", Target: "a.example.com:443", Vantage: "public", Severity: check.Medium},
	}
	got := map[string]check.Finding{}
	for _, f := range classifyGeo(in, views, geo) {
		got[f.Check+"@"+f.Vantage+"@"+f.Target] = f
	}
	for _, want := range []string{"geo.verified@vpn@vpn", "geo.bypass@vpn@b.example.com", "geo.unexpected-block@fr@a.example.com",
		"http.cdn-blocked@vpn@vpn", "http.hsts.absent@public@a.example.com:443"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s absent ; reçus %v", want, got)
		}
	}
	if _, ok := got["http.cdn-blocked@vpn@a.example.com:443"]; ok {
		t.Error("page de blocage par hôte conservée")
	}
}

func TestJudgeExposure(t *testing.T) {
	views := []exitView{{v: scan.ProxyVantage("etranger", nil), ip: exitIP, priv: map[string]bool{}}}
	exp := map[string]string{"admin.example.com": policy.Auth, "trou.example.com": policy.Auth, "pub.example.com": policy.Public}
	in := []check.Finding{
		{Check: "http.csp.no-script-src", Target: "admin.example.com:443", Vantage: "public", Severity: check.Medium},
		{Check: "http.csp.no-script-src", Target: "trou.example.com:443", Vantage: "public", Severity: check.Medium},
		{Check: "http.access.open", Target: "trou.example.com:443", Vantage: "etranger", Evidence: "statut 200"},
		{Check: "http.csp.no-script-src", Target: "pub.example.com:443", Vantage: "public", Severity: check.Medium},
		{Check: "http.hsts.absent", Target: "admin.example.com:443", Vantage: "public", Severity: check.Medium},
	}
	out := judgeExposure(in, views, exp)
	sev := map[string]check.Severity{}
	for _, f := range out {
		sev[f.Check+"@"+f.Target] = f.Severity
	}
	if sev["http.csp.no-script-src@admin.example.com:443"] != check.Low {
		t.Error("hygiène derrière authentification non abaissée")
	}
	if sev["http.csp.no-script-src@trou.example.com:443"] != check.Medium || sev["exposure.mismatch@trou.example.com"] != check.High {
		t.Error("une sortie a prouvé l'accès : pas d'abaissement, et un écart élevé")
	}
	if sev["http.csp.no-script-src@pub.example.com:443"] != check.Medium || sev["http.hsts.absent@admin.example.com:443"] != check.Medium {
		t.Error("abaissement hors de son périmètre")
	}
}

func TestOriginBypass(t *testing.T) {
	for _, c := range []struct {
		status int
		want   string
	}{{200, "origin.bypass"}, {403, "origin.closed"}} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status) }))
		u, _ := url.Parse(srv.URL)
		originPort, _ = strconv.Atoi(u.Port())
		originHTTPPort = closedPort(t)
		views := []exitView{{v: scan.Fixed("etranger", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{}}}
		fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), views, []string{"app.example.com"}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
		srv.Close()
		if len(fs) == 0 || fs[0].Check != c.want {
			t.Errorf("statut %d : %+v, attendu %s", c.status, fs, c.want)
		}
	}
	originPort, originHTTPPort = 443, 80
	// Sortie privilégiée : test sans valeur, donc rien.
	if fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), []exitView{{v: scan.Fixed("x"), priv: map[string]bool{"a": true}}}, []string{"a"}, []netip.Addr{netip.MustParseAddr("127.0.0.1")}); len(fs) != 0 {
		t.Errorf("sortie privilégiée testée : %+v", fs)
	}
}

func TestBannedExit(t *testing.T) {
	views := []exitView{{v: scan.ProxyVantage("be", nil), ip: exitIP, priv: map[string]bool{}}}
	var in []check.Finding
	for i := 0; i < 9; i++ {
		in = append(in, check.Finding{Check: "http.access.denied", Target: fmt.Sprintf("h%d.example.com:443", i), Vantage: "be"})
	}
	in = append(in, check.Finding{Check: "http.access.open", Target: "admin.example.com:443", Vantage: "be"})
	out := judgeExposure(in, views, map[string]string{"admin.example.com": policy.Auth})
	got := map[string]bool{}
	for _, f := range out {
		got[f.Check] = true
	}
	if !got["proxy.banned"] || !got["exposure.mismatch"] {
		t.Errorf("sortie bannie : %v (un « ouvert » prouve l'exposition même depuis une IP bannie)", got)
	}
}

func TestOriginBypassShortcut(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	originPort = ln.Addr().(*net.TCPAddr).Port
	originHTTPPort = originPort
	ln.Close() // port fermé : connexion refusée
	defer func() { originPort, originHTTPPort = 443, 80 }()
	var hosts []string
	for i := 0; i < 40; i++ {
		hosts = append(hosts, fmt.Sprintf("h%d.example.com", i))
	}
	start := time.Now()
	fs := originBypass(context.Background(), scan.NewGuard(1000, 2, 0),
		[]exitView{{v: scan.Fixed("etranger", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{}}}, hosts,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")})
	closed, skipped := counts(fs)
	// Chaque adresse et port a son compteur : tous sont testés même si le premier est filtré.
	if len(fs) != 1 || fs[0].Check != "origin.closed" || closed < 12 || closed+skipped != 160 {
		t.Errorf("constats : %+v", fs)
	}
	if el := time.Since(start); el > 5*time.Second {
		t.Errorf("%v pour 40 hôtes : l'arrêt anticipé n'a pas joué", el)
	}
}

func TestOriginBypassSkipsV6WithoutExitV6(t *testing.T) {
	ev := exitView{v: scan.Fixed("v4seul", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{}}
	fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), []exitView{ev}, []string{"a.example.com"},
		[]netip.Addr{netip.MustParseAddr("2001:db8::1")})
	if len(fs) != 1 || !strings.Contains(fs[0].Title, "non testée") || !strings.Contains(fs[0].Evidence, "IPv6 non testée") {
		t.Errorf("origine IPv6 testée depuis une sortie sans IPv6, ou absence non dite : %+v", fs)
	}
}

var exitIP = netip.MustParseAddr("203.0.113.50")

// Sortie à l'IP inconnue (hôtes hors Cloudflare) : mesures gardées, mais ni
// écart d'exposition ni contournement de l'origine conclus depuis elle.
func TestUnknownExitIP(t *testing.T) {
	views := []exitView{{v: scan.Fixed("x", netip.MustParseAddr("127.0.0.1")), priv: map[string]bool{}}}
	in := []check.Finding{{Check: "http.access.open", Target: "admin.example.com:443", Vantage: "x"}}
	for _, f := range judgeExposure(in, views, map[string]string{"admin.example.com": policy.Auth}) {
		if f.Check == "exposure.mismatch" {
			t.Errorf("écart conclu depuis une sortie inconnue : %+v", f)
		}
	}
	if fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), views, []string{"a"}, []netip.Addr{netip.MustParseAddr("127.0.0.1")}); len(fs) != 0 {
		t.Errorf("origine testée depuis une sortie inconnue : %+v", fs)
	}
}

func closedPort(t *testing.T) int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return p
}

// Port 80 de l'origine : servir le site est un contournement, renvoyer vers
// HTTPS (par le nom, donc par le CDN) ne l'est pas.
func TestOriginBypassHTTP(t *testing.T) {
	defer func() { originPort, originHTTPPort = 443, 80 }()
	views := []exitView{{v: scan.Fixed("etranger", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{}}}
	for _, c := range []struct {
		h    http.HandlerFunc
		want string
	}{
		{func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("site")) }, "origin.bypass"},
		{func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+"/", http.StatusMovedPermanently)
		}, "renvois vers HTTPS"},
	} {
		srv := httptest.NewServer(c.h)
		originPort = closedPort(t)
		originHTTPPort, _ = strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
		fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), views, []string{"app.example.com"}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
		srv.Close()
		got := fmt.Sprint(fs)
		if !strings.Contains(got, c.want) || (c.want != "origin.bypass" && strings.Contains(got, "origin.bypass{")) {
			t.Errorf("attendu %q : %s", c.want, got)
		}
	}
}

// Seuls les échecs de connexion TCP alimentent l'arrêt anticipé : une origine
// qui accepte la connexion puis rate TLS répond, chaque hôte est testé.
func TestOriginShortcutOnlyOnDial(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close() // TCP accepté, TLS impossible
		}
	}()
	originPort, originHTTPPort = ln.Addr().(*net.TCPAddr).Port, closedPort(t)
	defer func() { originPort, originHTTPPort = 443, 80 }()
	var hosts []string
	for i := 0; i < 10; i++ {
		hosts = append(hosts, fmt.Sprintf("h%d.example.com", i))
	}
	fs := originBypass(context.Background(), scan.NewGuard(1000, 2, 0),
		[]exitView{{v: scan.Fixed("etranger", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{}}}, hosts,
		[]netip.Addr{netip.MustParseAddr("127.0.0.1")})
	closed, skipped := counts(fs)
	// HTTPS : 10 réponses TLS ratées, jamais sautées ; HTTP (port fermé) : 3 échecs puis 7 sautés.
	if closed < 13 || skipped > 7 {
		t.Errorf("sans réponse %d, non testés %d : %+v", closed, skipped, fs)
	}
}

func TestExposureVerified(t *testing.T) {
	views := []exitView{{v: scan.ProxyVantage("vpn", nil), ip: exitIP, priv: map[string]bool{}}}
	in := []check.Finding{
		{Check: "http.access.auth", Target: "a.example.com:443", Vantage: "vpn"},
		{Check: "http.access.auth", Target: "b.example.com:443", Vantage: "vpn"},
		{Check: "http.access.open", Target: "pub.example.com:443", Vantage: "vpn"},
	}
	out := judgeExposure(in, views, map[string]string{"a.example.com": policy.Auth, "b.example.com": policy.Auth, "pub.example.com": policy.Public})
	var ok bool
	for _, f := range out {
		if f.Check == "exposure.verified" && strings.Contains(f.Title, "2/2") {
			ok = true
		}
	}
	if !ok {
		t.Errorf("preuve positive absente : %+v", out)
	}
}

func TestBuildTargetsKeepsPrivilegeReason(t *testing.T) {
	rt := source.Route{Name: "app", Hosts: []string{"app.example.com"}, Ports: []int{443},
		Middlewares: []source.Middleware{{Name: "lan", Kind: source.IPAllow, AllowFrom: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}}}}
	ts := buildTargets([]source.Route{rt}, policy.Options{Egress: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	if len(ts) != 1 || !ts[0].privileged || !strings.Contains(ts[0].why, "lan") {
		t.Errorf("cibles : %+v", ts)
	}
}

// counts lit « N sans réponse » et « N non testés » dans la preuve d'origin.closed.
func counts(fs []check.Finding) (closed, skipped int) {
	for _, f := range fs {
		if f.Check != "origin.closed" {
			continue
		}
		if m := regexp.MustCompile(`(\d+) sans réponse`).FindStringSubmatch(f.Evidence); m != nil {
			closed, _ = strconv.Atoi(m[1])
		}
		if m := regexp.MustCompile(`(\d+) non testés`).FindStringSubmatch(f.Evidence); m != nil {
			skipped, _ = strconv.Atoi(m[1])
		}
	}
	return
}

// Sortie en liste blanche : l'origine doit la servir ; un refus est signalé,
// et chaque famille est comptée à part.
func TestOriginAllowedExit(t *testing.T) {
	defer func() { originPort, originHTTPPort = 443, 80 }()
	for _, c := range []struct {
		status int
		want   string
	}{{200, "origin.allowed"}, {403, "origin.allowed-refused"}} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(c.status) }))
		u, _ := url.Parse(srv.URL)
		originPort, _ = strconv.Atoi(u.Port())
		originHTTPPort = closedPort(t)
		views := []exitView{{v: scan.Fixed("bureau", netip.MustParseAddr("127.0.0.1")), ip: exitIP, priv: map[string]bool{"app.example.com": true}}}
		fs := originBypass(context.Background(), scan.NewGuard(100, 2, 0), views, []string{"app.example.com", "autre.example.com"},
			[]netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2001:db8::1")})
		srv.Close()
		got := map[string]check.Finding{}
		for _, f := range fs {
			got[f.Check] = f
		}
		if _, ok := got[c.want]; !ok || got["origin.bypass"].Check != "" {
			t.Errorf("statut %d : %+v, attendu %s", c.status, fs, c.want)
		}
		if ev := got["origin.allowed"].Evidence + got["origin.allowed-refused"].Evidence; !strings.Contains(ev, "IPv4 :") {
			t.Errorf("famille absente : %q", ev)
		}
		if a := got["origin.allowed"]; c.status == 200 && !strings.Contains(a.Evidence, "IPv6 non testée") {
			t.Errorf("IPv6 non signalée : %q", a.Evidence)
		}
	}
}

func TestInternalRoutesDowngraded(t *testing.T) {
	views := []exitView{{v: scan.ProxyVantage("vpn", nil), ip: exitIP, priv: map[string]bool{}}}
	routes := []source.Route{{Name: "api@file", Ports: []int{8080}}, {Name: "pub@file", Ports: []int{443}}}
	fs := []check.Finding{
		{Check: "chain.problem", Target: "api@file", Vantage: "config", Severity: check.Low},
		{Check: "chain.problem", Target: "pub@file", Vantage: "config", Severity: check.Low},
		{Check: "port.open", Target: "198.51.100.7:443", Vantage: "vpn"},
	}
	out := internalRoutes(fs, routes, views, []int{443, 8080})
	if out[0].Severity != check.Info || out[1].Severity != check.Low {
		t.Errorf("api interne %v, route publique %v", out[0].Severity, out[1].Severity)
	}
	// Port non exploré : on ne sait pas, rien ne change.
	fs[0].Severity = check.Low
	if out := internalRoutes(fs, routes, views, []int{443}); out[0].Severity != check.Low {
		t.Error("port non exploré pris pour fermé")
	}
}
