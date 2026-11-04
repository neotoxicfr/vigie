package probe

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/html"
)

var (
	wapOnce sync.Once
	wap     *wappalyzer.Wappalyze
)

func (p *prober) content(r *response) {
	wapOnce.Do(func() { wap, _ = wappalyzer.New() })
	if wap != nil {
		var techs []string
		for name := range wap.Fingerprint(r.header, r.body) {
			techs = append(techs, name)
		}
		if len(techs) > 0 {
			sort.Strings(techs)
			p.add("http.tech", check.Info, "Technologies détectées", strings.Join(techs, ", "))
		}
	}
	// BREACH : un secret dans une réponse compressée peut se deviner octet par octet.
	if r.encoded != "" && r.encoded != "identity" &&
		(len(r.header.Values("Set-Cookie")) > 0 || tokenRe.Match(r.body)) {
		p.add("http.compression.secret", check.Info, "Réponse compressée contenant un jeton (BREACH à évaluer)", "Content-Encoding: "+r.encoded)
	}
	if strings.Contains(strings.ToLower(r.header.Get("Content-Type")), "html") {
		p.html(r)
	}
}

var tokenRe = regexp.MustCompile(`(?i)name=["']?(csrf|_csrf|csrf_token|_token|authenticity_token|requesttoken)|data-requesttoken=`)

// html relève les scripts et feuilles externes sans integrity (SRI) et les
// ressources HTTP sur une page HTTPS (contenu mixte).
func (p *prober) html(r *response) {
	z := html.NewTokenizer(bytes.NewReader(r.body))
	var noSRI, active, passive []string
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}
		tok := z.Token()
		attr := map[string]string{}
		for _, a := range tok.Attr {
			attr[strings.ToLower(a.Key)] = a.Val
		}
		var ref string
		isActive, sri := false, false
		switch tok.Data {
		case "script":
			ref, isActive, sri = attr["src"], true, true
		case "link":
			rel := strings.ToLower(attr["rel"])
			if strings.Contains(rel, "stylesheet") || strings.Contains(rel, "modulepreload") {
				ref, isActive, sri = attr["href"], true, true
			}
		case "iframe", "object", "embed":
			ref, isActive = attr["src"]+attr["data"], true
		case "img", "audio", "video", "source":
			ref = attr["src"]
		}
		if ref == "" {
			continue
		}
		u, err := r.url.Parse(strings.TrimSpace(ref))
		if err != nil {
			continue
		}
		if sri && u.Host != "" && !strings.EqualFold(u.Hostname(), r.url.Hostname()) {
			if _, ok := attr["integrity"]; !ok {
				noSRI = append(noSRI, u.String())
			}
		}
		if r.url.Scheme == "https" && u.Scheme == "http" {
			if isActive {
				active = append(active, u.String())
			} else {
				passive = append(passive, u.String())
			}
		}
	}
	if len(noSRI) > 0 {
		// Faible : le risque dépend de la confiance accordée au CDN tiers.
		p.add("http.sri.missing", check.Low, "Ressource externe sans contrôle d'intégrité (SRI)", strings.Join(noSRI, " "))
	}
	switch {
	case len(active) > 0:
		// Contenu actif en HTTP : un intermédiaire réécrit le script, donc la page.
		p.add("http.mixed-content", check.Medium, "Contenu mixte actif (script, style, cadre en HTTP)", strings.Join(append(active, passive...), " "))
	case len(passive) > 0:
		p.add("http.mixed-content", check.Low, "Contenu mixte passif (image, média en HTTP)", strings.Join(passive, " "))
	}
}

var (
	stackRe   = regexp.MustCompile(`Traceback \(most recent call last\)|\bat [a-z]+\.[A-Za-z.$]+\(\w+\.java:\d+\)|Stack trace:|Exception in thread|<b>Fatal error</b>|on line <b>\d+</b>|Whoops, looks like|System\.[A-Za-z.]+Exception|goroutine \d+ \[`)
	pathRe    = regexp.MustCompile(`(/var/www/|/home/[a-z]|/usr/(local/)?lib/|/srv/|[A-Z]:\\(inetpub|Users|Program))`)
	bannerRe  = regexp.MustCompile(`(?i)(apache|nginx|openresty|lighttpd|iis|tomcat|jetty|php|caddy|traefik)[/ ]v?\d+\.\d+`)
	gitHeadRe = regexp.MustCompile(`^(ref: refs/|[0-9a-f]{40}\s*$)`)
	envRe     = regexp.MustCompile(`(?m)^\s*(export\s+)?([A-Z][A-Z0-9_]{2,})\s*=`)
)

// verboseError juge la page d'erreur d'un chemin inexistant.
func (p *prober) verboseError(r *response) {
	if r.status < 400 {
		return
	}
	body := string(r.body)
	switch {
	case stackRe.MatchString(body):
		p.add("http.error.verbose", check.Medium, "Page d'erreur avec pile d'appels", stackRe.FindString(body))
	case pathRe.MatchString(body):
		p.add("http.error.verbose", check.Medium, "Page d'erreur révélant des chemins du serveur", pathRe.FindString(body))
	case bannerRe.MatchString(body):
		p.add("http.error.verbose", check.Low, "Page d'erreur révélant une version logicielle", bannerRe.FindString(body))
	}
}

type leak struct {
	id, path string
	sev      check.Severity
	title    string
	match    func(body []byte) string // preuve courte, vide si ce n'est pas le bon contenu
}

var leaks = []leak{
	{"git", "/.git/HEAD", check.High, "Dépôt Git exposé", func(b []byte) string {
		s := strings.TrimSpace(string(b))
		if gitHeadRe.MatchString(s) && len(s) < 200 {
			return s
		}
		return ""
	}},
	{"env", "/.env", check.High, "Fichier .env exposé", func(b []byte) string {
		if bytes.Contains(bytes.ToLower(b[:min(len(b), 512)]), []byte("<html")) {
			return ""
		}
		var names []string
		for _, m := range envRe.FindAllSubmatch(b, 10) {
			names = append(names, string(m[2])) // noms seulement, jamais les valeurs
		}
		if len(names) == 0 {
			return ""
		}
		return "variables : " + strings.Join(names, ", ")
	}},
	{"server-status", "/server-status", check.Medium, "Page d'état du serveur exposée", marker("Apache Server Status", "Server uptime", "Active connections:")},
	{"server-info", "/server-info", check.Medium, "Page de configuration du serveur exposée", marker("Apache Server Information", "Server Settings")},
	{"ds-store", "/.DS_Store", check.Low, "Fichier .DS_Store exposé (liste de fichiers)", func(b []byte) string {
		if bytes.HasPrefix(b, []byte("\x00\x00\x00\x01Bud1")) {
			return "en-tête Bud1"
		}
		return ""
	}},
	{"phpinfo", "/phpinfo.php", check.Medium, "phpinfo() exposé", marker("<title>phpinfo()", "PHP Version </td>", `class="e">PHP Version`)},
}

func marker(ms ...string) func([]byte) string {
	return func(b []byte) string {
		for _, m := range ms {
			if bytes.Contains(b, []byte(m)) {
				return m
			}
		}
		return ""
	}
}

func fingerprint(r *response) [32]byte {
	if r == nil {
		return [32]byte{}
	}
	return sha256.Sum256(r.body)
}

// leaks ne retient un 200 que si son contenu est celui attendu et diffère de
// la réponse d'un chemin inexistant (SPA qui répond 200 à tout).
func (p *prober) leaks(random *response) {
	generic := random != nil && random.status == http.StatusOK
	gfp := fingerprint(random)
	same := func(r *response) bool { return generic && fingerprint(r) == gfp }
	for _, l := range leaks {
		r, err := p.do(p.hc, http.MethodGet, p.url(l.path), nil, true)
		if err != nil {
			if p.stopped {
				return
			}
			continue
		}
		if r.status != http.StatusOK || same(r) {
			continue
		}
		if ev := l.match(r.body); ev != "" {
			p.add("http.leak."+l.id, l.sev, l.title, l.path+" : "+ev)
		}
	}
	r, err := p.do(p.hc, http.MethodGet, p.url("/.well-known/security.txt"), nil, true)
	if p.stopped {
		return
	}
	if err != nil || r.status != http.StatusOK || same(r) || !bytes.Contains(bytes.ToLower(r.body), []byte("contact:")) {
		p.add("http.securitytxt.absent", check.Info, "security.txt absent", "/.well-known/security.txt")
	}
	r, err = p.do(p.hc, http.MethodGet, p.url("/robots.txt"), nil, true)
	if err == nil && r.status == http.StatusOK && !same(r) {
		var lines []string
		for _, l := range strings.Split(string(r.body), "\n") {
			l = strings.TrimSpace(l)
			if low := strings.ToLower(l); strings.HasPrefix(low, "disallow:") || strings.HasPrefix(low, "allow:") {
				lines = append(lines, l)
			}
		}
		if len(lines) > 0 {
			p.add("http.robots", check.Info, "robots.txt liste des chemins", strings.Join(lines, " ; "))
		}
	}
}

var altSvcH3 = regexp.MustCompile(`\bh3="[^"]*:(\d+)"`)

// h3 essaie HTTP/3 si Alt-Svc l'annonce ; cassé, il fait attendre les
// navigateurs avant leur repli TCP (faible).
func (p *prober) h3(h http.Header) {
	m := altSvcH3.FindStringSubmatch(strings.Join(h.Values("Alt-Svc"), ","))
	if m == nil || p.stopped {
		return
	}
	port, err := strconv.Atoi(m[1])
	if err != nil || port < 1 || port > 65535 {
		return // le port déborderait uint16 : annonce ignorée
	}
	p.add("http.h3.advertised", check.Info, "HTTP/3 annoncé (Alt-Svc)", m[0])
	if p.v.Proxy != nil {
		return // un proxy TCP ne transporte pas l'UDP : pas d'essai HTTP/3 depuis cette sortie
	}
	err = p.tryH3(port)
	switch {
	case err == nil:
		p.add("http.h3.ok", check.Info, "HTTP/3 fonctionne", "port UDP "+m[1])
	case !p.stopped:
		p.add("http.h3.broken", check.Low, "HTTP/3 annoncé mais injoignable", err.Error())
	}
}

func (p *prober) tryH3(port int) error {
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	addrs, err := p.v.Addrs(ctx, p.t.Host)
	if err != nil {
		return err
	}
	release, err := p.g.Acquire(ctx, p.t.Host)
	if err != nil {
		p.stopped = true
		return err
	}
	defer release()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: p.t.Host, RootCAs: rootCAs, InsecureSkipVerify: p.insecure}, //nolint:gosec // même règle que TCP
		Dial: func(ctx context.Context, _ string, tc *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			var errs []error
			for _, a := range addrs {
				c, err := quic.DialAddr(ctx, netip.AddrPortFrom(a, uint16(port)).String(), tc, qc)
				if err == nil {
					return c, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
	defer tr.Close()
	u := url.URL{Scheme: "https", Host: p.base.Host, Path: "/"}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := tr.RoundTrip(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		p.g.Suspend(p.t.Host, "429 sur HTTP/3")
		p.stopped = true
		return errStop
	}
	return nil
}
