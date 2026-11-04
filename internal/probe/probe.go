// Package probe audite la configuration HTTP d'une cible : en-têtes de
// sécurité, cookies, CORS, méthodes, redirections, fuites de fichiers,
// HTTP/2, HTTP/3, WebSocket et SSE. Requêtes légères et passives uniquement.
package probe

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

const (
	maxBody     = 256 << 10
	maxHops     = 5
	maxEvidence = 300
)

// rootCAs nil = racines du système ; les tests y mettent leur autorité.
var rootCAs *x509.CertPool

// httpPort : port HTTP clair dont on attend une redirection vers HTTPS (variable pour les tests).
var httpPort = 80

var errStop = errors.New("cible arrêtée")

type prober struct {
	ctx      context.Context
	g        *scan.Guard
	v        scan.Vantage
	t        scan.Target
	base     *url.URL
	insecure bool
	hc, h1   *http.Client
	trs      []*http.Transport
	out      []check.Finding
	stopped  bool
}

type response struct {
	url     *url.URL
	status  int
	header  http.Header
	body    []byte
	proto   string
	alpn    string
	encoded string // Content-Encoding reçu
	loc     *url.URL
}

// Check lance tous les contrôles HTTP sur t depuis le point de vue v.
func Check(ctx context.Context, g *scan.Guard, v scan.Vantage, t scan.Target) []check.Finding {
	p := &prober{ctx: ctx, g: g, v: v, t: t}
	scheme := "http"
	if t.TLS || t.Port == 443 {
		scheme = "https"
	}
	host := t.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if t.Port != 0 && !(scheme == "https" && t.Port == 443) && !(scheme == "http" && t.Port == 80) {
		host += ":" + strconv.Itoa(t.Port)
	}
	p.base = &url.URL{Scheme: scheme, Host: host, Path: "/"}
	if u, err := url.Parse(t.Page); err == nil && strings.HasPrefix(u.Path, "/") {
		p.base.Path, p.base.RawQuery = u.Path, u.RawQuery
	}
	p.clients()
	defer func() {
		for _, tr := range p.trs {
			tr.CloseIdleConnections()
		}
	}()
	p.run()
	return p.out
}

func (p *prober) clients() {
	noFollow := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	p.trs = []*http.Transport{p.transport(true), p.transport(false)}
	p.hc = &http.Client{Transport: p.trs[0], CheckRedirect: noFollow, Timeout: 30 * time.Second}
	p.h1 = &http.Client{Transport: p.trs[1], CheckRedirect: noFollow, Timeout: 30 * time.Second}
}

// transport : une connexion par requête (DisableKeepAlives) pour que chacune
// passe par le garde et lui rende sa place à la fin.
func (p *prober) transport(h2 bool) *http.Transport {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, ps, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			port, _ := strconv.Atoi(ps)
			return p.g.Dial(ctx, p.v, h, port)
		},
		TLSClientConfig:       &tls.Config{RootCAs: rootCAs, InsecureSkipVerify: p.insecure}, //nolint:gosec // audit d'un certificat déjà signalé invalide
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ForceAttemptHTTP2:     h2,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}
	if !h2 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	return tr
}

func (p *prober) add(id string, sev check.Severity, title, evidence string) {
	target := p.t.String()
	p.out = append(p.out, check.Finding{Check: id, Target: target, Vantage: p.v.Name,
		Severity: sev, Title: title, Evidence: trunc(evidence)})
}

func trunc(s string) string {
	s = strings.ToValidUTF8(s, "?")
	if len(s) <= maxEvidence {
		return s
	}
	cut := maxEvidence - 3
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func (p *prober) url(path string) *url.URL {
	u := *p.base
	u.Path, u.RawQuery = path, ""
	return &u
}

func (p *prober) inScope(host string) bool {
	if strings.EqualFold(host, p.t.Host) {
		return true
	}
	if p.t.Route != nil {
		for _, h := range p.t.Route.Hosts {
			if strings.EqualFold(h, host) {
				return true
			}
		}
	}
	return false
}

// do envoie une requête ; read lit le corps (borné), sinon seuls statut et
// en-têtes comptent et la connexion est fermée aussitôt.
func (p *prober) do(c *http.Client, method string, u *url.URL, hdr http.Header, read bool) (*response, error) {
	if p.stopped {
		return nil, errStop
	}
	req, err := http.NewRequestWithContext(p.ctx, method, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	if method == http.MethodGet {
		req.Header.Set("Accept-Encoding", "gzip")
	}
	for k, vs := range hdr {
		req.Header[k] = vs
	}
	resp, err := c.Do(req)
	if err != nil {
		if errors.Is(err, scan.ErrSuspended) || errors.Is(err, scan.ErrBudget) || p.ctx.Err() != nil {
			p.stopped = true
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		p.g.Suspend(u.Hostname(), "429 sur "+method+" "+u.Path)
		p.stopped = true
		return nil, errStop
	}
	r := &response{url: u, status: resp.StatusCode, header: resp.Header, proto: resp.Proto,
		encoded: strings.ToLower(resp.Header.Get("Content-Encoding"))}
	if resp.TLS != nil {
		r.alpn = resp.TLS.NegotiatedProtocol
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if l, err := resp.Location(); err == nil {
			r.loc = l
		}
	}
	if read && method != http.MethodHead {
		var rd io.Reader = io.LimitReader(resp.Body, maxBody)
		if r.encoded == "gzip" {
			if z, err := gzip.NewReader(rd); err == nil {
				rd = io.LimitReader(z, maxBody)
			}
		}
		r.body, _ = io.ReadAll(rd)
	}
	return r, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *prober) run() {
	first, err := p.do(p.hc, http.MethodGet, p.base, nil, true)
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		p.add("http.tls.unverified", check.Medium, "Certificat TLS non vérifiable", err.Error())
		p.insecure = true
		p.clients()
		first, err = p.do(p.hc, http.MethodGet, p.base, nil, true)
	}
	if err != nil {
		if !p.stopped {
			p.add("http.unreachable", check.Info, "Cible injoignable en HTTP", err.Error())
		}
		return
	}
	if why := cdnBlock(first); why != "" {
		// Page de blocage du CDN (géo, WAF, défi) : ses en-têtes ne sont pas ceux du
		// site ; un seul constat, et rien de plus depuis ce point de vue.
		p.add("http.cdn-blocked", check.Info, "Bloqué par le CDN avant le site", why)
		return
	}
	if first.url.Scheme == "https" {
		if first.alpn == "h2" {
			p.add("http.alpn.h2", check.Info, "HTTP/2 négocié (ALPN h2)", first.proto)
		} else {
			p.add("http.alpn.h2-absent", check.Info, "HTTP/2 non proposé en ALPN", "ALPN : "+first.alpn)
		}
	}

	chain, last, foreign := p.follow(first)
	if p.base.Scheme == "http" && p.t.Port == httpPort {
		if first.loc == nil || first.url.ResolveReference(first.loc).Scheme != "https" {
			ev := "statut " + strconv.Itoa(first.status)
			if first.loc != nil {
				ev += " vers " + first.loc.String()
			}
			p.add("http.redirect.https", check.Medium, "Pas de redirection immédiate vers HTTPS", ev)
		} else {
			// Les en-têtes de la page HTTPS relèvent de la cible HTTPS.
			return
		}
	}
	if p.stopped {
		return
	}
	authRequired := foreign || first.status == http.StatusUnauthorized || first.status == http.StatusForbidden
	if p.v.Proxy != nil && (authRequired || last.status == http.StatusUnauthorized || last.status == http.StatusForbidden) {
		// Depuis une sortie, un portail d'authentification ou un refus est tout ce que
		// voit l'inconnu : on le note, sans juger les en-têtes du portail (l'hôte du
		// portail est audité pour lui-même).
		p.access(first, last, foreign)
		return
	}

	// Refus ou renvoi vers un portail : la page reçue est celle du contrôle d'accès,
	// pas de l'application ; ses en-têtes, cookies et contenu ne disent rien d'elle.
	gated := authRequired || last.status == http.StatusUnauthorized || last.status == http.StatusForbidden
	if gated {
		ev := "statut " + strconv.Itoa(last.status)
		if last.loc != nil {
			ev += " vers " + last.url.ResolveReference(last.loc).String()
		}
		p.add("http.auth.session-required", check.Info, "Non mesurable sans session : contrôle d'accès devant l'application", ev)
	} else {
		p.cookies(chain)
	}
	if last.url.Scheme == "https" {
		p.hsts(last.header) // vaut pour tout l'hôte, portail compris
	}
	if !gated && (last.status < 300 || last.status >= 400) {
		p.headers(last.header)
		p.content(last)
	}
	p.serverVersion(last.header)
	if !gated {
		p.cache(last)
	}
	if p.v.Proxy != nil {
		// Sortie par proxy : on garde ce qu'un inconnu voit vraiment (accès, en-têtes,
		// cookies) ; fuites, méthodes, CORS, flux et HTTP/3 sont déjà mesurés côté public.
		p.access(first, last, foreign)
		return
	}

	random, _ := p.do(p.hc, http.MethodGet, p.url("/vigie-"+randHex(8)), nil, true)
	if random != nil {
		p.verboseError(random)
	}
	p.leaks(random)
	p.methods()
	p.cors()
	p.streams(authRequired)
	p.h3(first.header)
}

// follow suit les redirections de « / » à la main, tant qu'elles restent chez
// la cible ; foreign indique un renvoi vers une autre origine (portail d'auth…).
func (p *prober) follow(first *response) (chain []*response, last *response, foreign bool) {
	chain = []*response{first}
	last = first
	var hops []string
	insecure := ""
	insecureHSTS := false
	for last.loc != nil {
		next := last.url.ResolveReference(last.loc)
		hops = append(hops, next.String())
		if last.url.Scheme == "https" && next.Scheme == "http" && insecure == "" {
			insecure = last.url.String() + " -> " + next.String()
			insecureHSTS = hstsLong(last.header)
		}
		if !p.inScope(next.Hostname()) || authPortal(p.base, next) || (next.Scheme != "http" && next.Scheme != "https") {
			foreign = true
			break
		}
		if len(hops) > maxHops {
			break
		}
		r, err := p.do(p.hc, http.MethodGet, next, nil, true)
		if err != nil {
			break
		}
		chain = append(chain, r)
		last = r
	}
	if insecure != "" {
		// Avec un HSTS long sur l'hôte, le navigateur réécrit ce saut en HTTPS
		// avant de l'envoyer : défaut réel mais sans fuite en clair.
		if insecureHSTS {
			p.add("http.redirect.insecure-hop", check.Low, "Redirection de HTTPS vers HTTP (couverte par HSTS)", insecure+" ; HSTS long présent")
		} else {
			p.add("http.redirect.insecure-hop", check.Medium, "Redirection de HTTPS vers HTTP", insecure)
		}
	}
	// Au-delà de 3 sauts, chaque visite paie plusieurs allers-retours ; plus de 5 = boucle probable.
	if len(hops) > 3 {
		p.add("http.redirect.chain-long", check.Low, "Chaîne de redirections longue", strconv.Itoa(len(hops))+" sauts : "+strings.Join(hops, " -> "))
	}
	return chain, last, foreign
}

// authPortal : renvoi vers un autre hôte qui emporte l'adresse de départ dans sa
// requête (rd=, next=, redirect_uri=…) : un portail d'authentification, même
// audité par ailleurs, dont la page n'est pas celle de la cible.
func authPortal(from, next *url.URL) bool {
	if strings.EqualFold(next.Hostname(), from.Hostname()) {
		return false
	}
	q, err := url.QueryUnescape(next.RawQuery)
	if err != nil {
		q = next.RawQuery
	}
	return strings.Contains(strings.ToLower(q), strings.ToLower(from.Hostname()))
}

func (p *prober) methods() {
	if r, err := p.do(p.hc, http.MethodOptions, p.base, nil, false); err == nil {
		if allow := r.header.Get("Allow"); allow != "" {
			p.add("http.method.list", check.Info, "Méthodes annoncées par OPTIONS", "Allow: "+allow)
		}
	}
	// TRACE renvoie la requête, cookies compris : vol possible (XST). Moyen comme ZAP.
	if r, err := p.do(p.h1, http.MethodTrace, p.base, nil, true); err == nil && r.status == http.StatusOK {
		ct := r.header.Get("Content-Type")
		if strings.HasPrefix(ct, "message/http") || strings.Contains(string(r.body), "TRACE /") {
			p.add("http.method.trace", check.Medium, "Méthode TRACE active", "statut 200, Content-Type: "+ct)
		}
	}
}

func (p *prober) cors() {
	foreign := "https://vigie-" + randHex(4) + ".example"
	for _, origin := range []string{foreign, "null"} {
		r, err := p.do(p.hc, http.MethodGet, p.base, http.Header{"Origin": {origin}}, false)
		if err != nil {
			return
		}
		acao := r.header.Get("Access-Control-Allow-Origin")
		creds := strings.EqualFold(r.header.Get("Access-Control-Allow-Credentials"), "true")
		ev := "Access-Control-Allow-Origin: " + acao + ", Allow-Credentials: " + strconv.FormatBool(creds)
		switch {
		case origin == "null" && acao == "null":
			// Origine null = iframe sandbox ou fichier local, forgeable par n'importe quel site.
			p.add("http.cors.null-origin", sevCreds(creds), "CORS accepte l'origine null", ev)
		case origin != "null" && acao == origin:
			p.add("http.cors.reflect-origin", sevCreds(creds), "CORS renvoie n'importe quelle origine", ev)
		case origin != "null" && acao == "*" && creds:
			// Refusé par les navigateurs : erreur de configuration plus que faille.
			p.add("http.cors.wildcard-credentials", check.Low, "CORS joker avec identifiants", ev)
		}
	}
}

// sevCreds : avec identifiants, un site tiers lit les réponses authentifiées (élevé) ;
// sans, seulement les données publiques (faible).
func sevCreds(creds bool) check.Severity {
	if creds {
		return check.High
	}
	return check.Low
}

// streams teste WebSocket et SSE ; ouverts alors que « / » exige une
// authentification, ils contournent probablement le portail.
func (p *prober) streams(authRequired bool) {
	paths := append([]string{"/"}, p.t.Paths...)
	seen := map[string]bool{}
	var ws, sse []string
	for _, path := range paths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		key := make([]byte, 16)
		_, _ = rand.Read(key)
		h := http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"},
			"Sec-Websocket-Key": {base64.StdEncoding.EncodeToString(key)}, "Sec-Websocket-Version": {"13"}}
		if r, err := p.do(p.h1, http.MethodGet, p.url(path), h, false); err == nil && r.status == http.StatusSwitchingProtocols {
			ws = append(ws, path)
		}
		if path == "/" {
			continue
		}
		if r, err := p.do(p.hc, http.MethodGet, p.url(path), http.Header{"Accept": {"text/event-stream"}}, false); err == nil &&
			r.status == http.StatusOK && strings.HasPrefix(r.header.Get("Content-Type"), "text/event-stream") {
			sse = append(sse, path)
		}
	}
	if len(ws) > 0 {
		p.add("http.ws.open", check.Info, "WebSocket accepté", strings.Join(ws, " "))
		if authRequired {
			p.add("http.ws.unprotected", check.High, "WebSocket ouvert sans l'authentification exigée par la page", strings.Join(ws, " "))
		}
	}
	if len(sse) > 0 && authRequired {
		p.add("http.sse.unprotected", check.High, "Flux SSE ouvert sans l'authentification exigée par la page", strings.Join(sse, " "))
	}
}

// cdnBlock reconnaît une page de blocage ou de défi de Cloudflare (règle de
// pare-feu, géo, robot) ; "" sinon.
func cdnBlock(r *response) string {
	if r.status != http.StatusForbidden && r.status != http.StatusTooManyRequests && r.status != http.StatusServiceUnavailable {
		return ""
	}
	if r.header.Get("Cf-Ray") == "" && !strings.EqualFold(r.header.Get("Server"), "cloudflare") {
		return ""
	}
	body := strings.ToLower(string(r.body))
	switch {
	case r.header.Get("Cf-Mitigated") != "":
		return "Cloudflare : défi (" + r.header.Get("Cf-Mitigated") + "), statut " + strconv.Itoa(r.status)
	case strings.Contains(body, "cf-error-details") || strings.Contains(body, "error code: 10") ||
		strings.Contains(body, "attention required") || strings.Contains(body, "sorry, you have been blocked") ||
		strings.Contains(body, "just a moment"):
		return "Cloudflare : page de blocage, statut " + strconv.Itoa(r.status) + ", Cf-Ray " + r.header.Get("Cf-Ray")
	}
	return ""
}

// access résume ce que la sortie obtient de « / » : page servie, portail
// d'authentification (renvoi vers une autre origine, 401) ou refus. Le moteur
// le confronte à l'exposition déduite de la configuration.
func (p *prober) access(first, last *response, foreign bool) {
	ev := "statut " + strconv.Itoa(first.status)
	if first.loc != nil {
		ev += " vers " + first.url.ResolveReference(first.loc).String()
	}
	switch {
	case foreign || last.status == http.StatusUnauthorized || first.status == http.StatusUnauthorized:
		p.add("http.access.auth", check.Info, "Depuis cette sortie : portail d'authentification", ev)
	case last.status == http.StatusForbidden || last.status == http.StatusNotFound && first.status == http.StatusNotFound:
		p.add("http.access.denied", check.Info, "Depuis cette sortie : accès refusé", ev)
	case last.status < 400:
		p.add("http.access.open", check.Info, "Depuis cette sortie : page servie sans authentification", ev)
	default:
		p.add("http.access.error", check.Info, "Depuis cette sortie : erreur du serveur", ev)
	}
}

// hstsLong : HSTS d'au moins six mois.
func hstsLong(h http.Header) bool {
	for _, part := range strings.Split(h.Get("Strict-Transport-Security"), ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(k, "max-age") {
			n, err := strconv.Atoi(strings.Trim(v, `"`))
			return err == nil && n >= 15552000
		}
	}
	return false
}
