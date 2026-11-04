// Package cloudflare lit la configuration d'une zone Cloudflare par l'API v4,
// en lecture seule, avec un jeton porteur.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/neotoxicfr/vigie/internal/cdnprov"
	"github.com/neotoxicfr/vigie/internal/check"
)

const (
	officialAPI = "https://api.cloudflare.com/client/v4"
	maxBody     = 8 << 20
	maxPages    = 50
	vantage     = "config"
)

// Permissions du jeton, au nom exact de l'interface Cloudflare.
const (
	permZone     = "Zone Read"
	permSettings = "Zone Settings Read"
	permSSL      = "SSL and Certificates Read"
	permDNS      = "DNS Read"
	permWAF      = "Zone WAF Read"
)

type Cloudflare struct {
	tokenFile string
	base      string
	client    *http.Client
}

// New : baseURL vide = API officielle (un autre sert aux tests).
// GlobalKeyMsg : la Global API Key ouvre tout le compte en écriture ; vigie ne
// l'accepte pas et demande un jeton restreint en lecture.
const GlobalKeyMsg = "cloudflare : ce fichier contient la Global API Key (37 caractères hexadécimaux), pas un jeton API. " +
	"Crée un jeton restreint en lecture (Mon profil > Jetons d'API > Créer un jeton : Zone Read, Zone Settings Read, " +
	"SSL and Certificates Read, DNS Read, Zone WAF Read) et mets-le à la place"

var globalKey = regexp.MustCompile(`^[0-9a-f]{37}$`)

// IsGlobalKey reconnaît le format de la Global API Key (les jetons API font 40 caractères).
func IsGlobalKey(token string) bool { return globalKey.MatchString(token) }

func New(tokenFile, baseURL string) *Cloudflare {
	if baseURL == "" {
		baseURL = officialAPI
	}
	return &Cloudflare{
		tokenFile: tokenFile,
		base:      strings.TrimRight(baseURL, "/"),
		client: &http.Client{
			Timeout: 20 * time.Second,
			// Pas de redirection : le jeton ne doit partir que vers l'API.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *Cloudflare) Name() string { return "cloudflare" }

// errScope : jeton refusé (invalide ou permission manquante).
var errScope = errors.New("accès refusé")

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type envelope struct {
	Success    bool            `json:"success"`
	Errors     []apiError      `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

type session struct {
	c     *Cloudflare
	ctx   context.Context
	token string
}

// get appelle l'API ; status vaut le code HTTP (404 laissé à l'appelant).
func (s *session) get(path string, q url.Values, out any) (env envelope, status int, err error) {
	u := s.c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, u, nil)
	if err != nil {
		return env, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+s.token)
	req.Header.Set("Accept", "application/json")
	resp, err := s.c.client.Do(req)
	if err != nil {
		// L'erreur de transport cite l'URL, jamais les en-têtes.
		return env, 0, fmt.Errorf("cloudflare : GET %s : %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return env, resp.StatusCode, fmt.Errorf("cloudflare : GET %s : %w", path, err)
	}
	if len(body) > maxBody {
		return env, resp.StatusCode, fmt.Errorf("cloudflare : GET %s : réponse de plus de 8 Mo", path)
	}
	_ = json.Unmarshal(body, &env)
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return env, resp.StatusCode, errScope
	case resp.StatusCode == http.StatusNotFound:
		return env, resp.StatusCode, nil
	case resp.StatusCode < 200 || resp.StatusCode > 299 || !env.Success: // certains points (origin_tls_client_auth) répondent 202
		return env, resp.StatusCode, fmt.Errorf("cloudflare : GET %s : HTTP %d%s", path, resp.StatusCode, s.describe(env.Errors))
	}
	if out != nil {
		if err := json.Unmarshal(env.Result, out); err != nil {
			return env, resp.StatusCode, fmt.Errorf("cloudflare : GET %s : réponse illisible : %w", path, err)
		}
	}
	return env, resp.StatusCode, nil
}

// describe résume les erreurs de l'API ; le jeton est masqué au cas où le
// message le citerait.
func (s *session) describe(errs []apiError) string {
	var b strings.Builder
	for i, e := range errs {
		if i == 3 {
			break
		}
		fmt.Fprintf(&b, " ; %d %s", e.Code, e.Message)
	}
	out := b.String()
	if s.token != "" {
		out = strings.ReplaceAll(out, s.token, "***")
	}
	if r := []rune(out); len(r) > 200 {
		out = string(r[:200]) + "…"
	}
	return out
}

// list lit toutes les pages d'une collection (per_page=100, 50 pages au plus).
func list[T any](s *session, path string) ([]T, error) {
	var all []T
	for page := 1; page <= maxPages; page++ {
		var items []T
		q := url.Values{"page": {fmt.Sprint(page)}, "per_page": {"100"}}
		env, _, err := s.get(path, q, &items)
		if err != nil {
			return all, err
		}
		all = append(all, items...)
		if env.ResultInfo.TotalPages <= page || len(items) == 0 {
			return all, nil
		}
	}
	return all, fmt.Errorf("cloudflare : GET %s : plus de %d pages, liste tronquée", path, maxPages)
}

type zoneScan struct {
	*session
	name    string
	id      string
	hosts   []string
	res     *cdnprov.Result
	missing []string // permissions manquantes
	direct  []record // enregistrements hors proxy, jugés quand toutes les origines sont connues
	errs    []error
}

func (z *zoneScan) add(id string, sev check.Severity, target, title, evidence string) {
	z.res.Findings = append(z.res.Findings, check.Finding{Check: id, Target: target, Vantage: vantage,
		Severity: sev, Title: title, Evidence: clip(evidence)})
}

// fail range l'erreur : refus → permission manquante, sinon erreur rendue.
func (z *zoneScan) fail(err error, perm string) {
	if errors.Is(err, errScope) {
		if !slices.Contains(z.missing, perm) {
			z.missing = append(z.missing, perm)
		}
		return
	}
	z.errs = append(z.errs, err)
}

// Scan lit, pour chaque zone des hôtes, réglages TLS, DNS, DNSSEC et règles de
// pare-feu. Un refus de l'API devient cf.token.scope et la suite continue.
func (c *Cloudflare) Scan(ctx context.Context, hosts []string) (cdnprov.Result, error) {
	res := cdnprov.Result{Notes: map[string]string{}, Proxied: map[string]bool{}, Geo: map[string]cdnprov.Geo{}}
	raw, err := os.ReadFile(c.tokenFile)
	if err != nil {
		return res, fmt.Errorf("cloudflare : lecture du jeton : %w", err)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return res, fmt.Errorf("cloudflare : jeton vide ou mal formé dans %s", c.tokenFile)
	}
	if IsGlobalKey(token) {
		return res, errors.New(GlobalKeyMsg)
	}
	s := &session{c: c, ctx: ctx, token: token}

	zones := map[string][]string{}
	var errs []error
	for _, h := range hosts {
		h = strings.TrimSuffix(strings.ToLower(h), ".")
		if h == "" {
			continue
		}
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		z, err := publicsuffix.EffectiveTLDPlusOne(h)
		if err != nil {
			continue
		}
		if !slices.Contains(zones[z], h) {
			zones[z] = append(zones[z], h)
		}
	}
	names := make([]string, 0, len(zones))
	for z := range zones {
		names = append(names, z)
	}
	slices.Sort(names)
	var scanned []*zoneScan
	for _, name := range names {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		z := &zoneScan{session: s, name: name, hosts: zones[name], res: &res}
		z.scan()
		scanned = append(scanned, z)
		if len(z.missing) > 0 {
			z.add("cf.token.scope", check.Medium, name, "Jeton Cloudflare sans les permissions nécessaires",
				"refusé : "+strings.Join(z.missing, ", ")+" (jeton invalide, ou permission absente pour cette zone)")
		}
		errs = append(errs, z.errs...)
	}
	for _, z := range scanned {
		z.judgeDirect()
	}
	return res, errors.Join(errs...)
}

func (z *zoneScan) scan() {
	var found []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if _, _, err := z.get("/zones", url.Values{"name": {z.name}}, &found); err != nil {
		z.fail(err, permZone)
		return
	}
	for _, f := range found {
		if strings.EqualFold(f.Name, z.name) {
			z.id = f.ID
		}
	}
	if z.id == "" {
		z.add("cf.zone.missing", check.Info, z.name, "Zone absente du compte Cloudflare",
			"aucune zone "+z.name+" visible avec ce jeton")
		return
	}
	z.settings()
	z.aop()
	z.dnssec()
	z.dns()
	z.waf()
}

func (z *zoneScan) path(p string) string { return "/zones/" + url.PathEscape(z.id) + p }

func (z *zoneScan) setting(id string, out any) bool {
	var s struct {
		Value json.RawMessage `json:"value"`
	}
	_, status, err := z.get(z.path("/settings/"+id), nil, &s)
	if err != nil {
		z.fail(err, permSettings)
		return false
	}
	return status/100 == 2 && json.Unmarshal(s.Value, out) == nil
}

func (z *zoneScan) settings() {
	var ssl string
	if z.setting("ssl", &ssl) {
		switch ssl {
		case "off":
			z.add("cf.ssl.off", check.High, z.name, "Cloudflare sert le site sans HTTPS",
				"mode SSL/TLS : off")
		case "flexible":
			z.add("cf.ssl.flexible", check.High, z.name, "Cloudflare joint l'origine en HTTP clair",
				"mode SSL/TLS : flexible (navigateur → Cloudflare chiffré, Cloudflare → origine en clair)")
		case "full":
			z.add("cf.ssl.full", check.Medium, z.name, "Cloudflare ne vérifie pas le certificat de l'origine",
				"mode SSL/TLS : full (certificat de l'origine accepté sans vérification) ; préférer strict")
		}
	}
	var minTLS string
	if z.setting("min_tls_version", &minTLS) && (minTLS == "1.0" || minTLS == "1.1") {
		z.add("cf.tls.min", check.Medium, z.name, "Cloudflare accepte TLS 1.0 ou 1.1",
			"min_tls_version : "+minTLS)
	}
	var https string
	if z.setting("always_use_https", &https) && https == "off" {
		z.add("cf.https.not-forced", check.Medium, z.name, "Cloudflare ne force pas HTTPS",
			"always_use_https : off")
	}
	var sh struct {
		STS struct {
			Enabled bool `json:"enabled"`
		} `json:"strict_transport_security"`
	}
	if z.setting("security_header", &sh) && !sh.STS.Enabled {
		z.add("cf.hsts.off", check.Info, z.name, "HSTS non posé par Cloudflare",
			"security_header.strict_transport_security.enabled : false (l'origine peut le poser elle-même)")
	}
}

func (z *zoneScan) aop() {
	var r struct {
		Enabled bool `json:"enabled"`
	}
	_, status, err := z.get(z.path("/origin_tls_client_auth/settings"), nil, &r)
	if err != nil {
		z.fail(err, permSSL)
		return
	}
	if status/100 == 2 && !r.Enabled {
		z.add("cf.aop.off", check.Low, z.name, "Authenticated Origin Pulls désactivé",
			"l'origine accepte des connexions TLS qui ne viennent pas de Cloudflare ; une liste blanche des IP Cloudflare devant l'origine compense")
	}
}

func (z *zoneScan) dnssec() {
	var r struct {
		Status string `json:"status"`
	}
	_, status, err := z.get(z.path("/dnssec"), nil, &r)
	if err != nil {
		z.fail(err, permDNS)
		return
	}
	if status/100 == 2 && r.Status != "active" {
		st := r.Status
		if st == "" {
			st = "inconnu"
		}
		z.add("cf.dnssec.off", check.Low, z.name, "DNSSEC non actif chez Cloudflare", "statut DNSSEC : "+st)
	}
}

type record struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}

func (z *zoneScan) dns() {
	recs, err := list[record](z.session, z.path("/dns_records"))
	if err != nil {
		z.fail(err, permDNS)
		if len(recs) == 0 {
			return
		}
	}
	for _, r := range recs {
		if a, err := netip.ParseAddr(r.Content); err == nil && r.Proxied && (r.Type == "A" || r.Type == "AAAA") {
			if a = a.Unmap(); a.IsGlobalUnicast() && !a.IsPrivate() && !slices.Contains(z.res.Origins, a) {
				z.res.Origins = append(z.res.Origins, a)
			}
		}
	}
	type state struct{ proxied, direct bool }
	byName := map[string]*state{}
	for _, r := range recs {
		if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(r.Name), ".")
		st := byName[name]
		if st == nil {
			st = &state{}
			byName[name] = st
		}
		if r.Proxied {
			st.proxied = true
			continue
		}
		st.direct = true
		r.Name = name
		z.direct = append(z.direct, r)
	}
	for _, h := range z.hosts {
		st := byName[h]
		if st == nil {
			// Joker du niveau juste au-dessus.
			if i := strings.IndexByte(h, '.'); i > 0 {
				st = byName["*"+h[i:]]
			}
		}
		if st != nil {
			// Un seul enregistrement direct suffit à contourner le CDN.
			z.res.Proxied[h] = st.proxied && !st.direct
		}
	}
}

// judgeDirect juge les enregistrements hors proxy une fois les origines de
// toutes les zones connues : une zone peut viser l'origine apprise dans une autre.
func (z *zoneScan) judgeDirect() {
	var unproxied []string
	for _, r := range z.direct {
		if a, err := netip.ParseAddr(r.Content); err == nil && slices.Contains(z.res.Origins, a.Unmap()) {
			z.add("cf.dns.origin-exposed", check.High, r.Name, "Le DNS public révèle l'adresse de l'origine",
				r.Type+" "+r.Name+" → "+r.Content+" non proxifié : Cloudflare est contournable")
			continue
		}
		if !slices.Contains(unproxied, r.Name) {
			unproxied = append(unproxied, r.Name)
		}
	}
	if len(unproxied) > 0 {
		slices.Sort(unproxied)
		z.add("cf.dns.unproxied", check.Info, z.name, "Enregistrements DNS hors du proxy Cloudflare",
			strings.Join(unproxied, ", "))
	}
}

type rule struct {
	Action      string `json:"action"`
	Expression  string `json:"expression"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

func (z *zoneScan) waf() {
	var rs struct {
		Rules []rule `json:"rules"`
	}
	_, status, err := z.get(z.path("/rulesets/phases/http_request_firewall_custom/entrypoint"), nil, &rs)
	if err != nil {
		z.fail(err, permWAF)
		return
	}
	var parts []string
	var geo cdnprov.Geo
	if status/100 == 2 {
		for _, r := range rs.Rules {
			if r.Enabled != nil && !*r.Enabled {
				continue
			}
			parts = append(parts, summarize(r.Action, r.Expression, r.Description)...)
			if r.Action == "block" {
				allowed, blocked := countries(r.Expression)
				geo.Allowed = append(geo.Allowed, allowed...)
				geo.Blocked = append(geo.Blocked, blocked...)
			}
		}
	}
	summary := "aucune règle de pare-feu personnalisée active"
	if len(parts) > 0 {
		summary = strings.Join(parts, " ; ")
	}
	z.add("cf.waf.summary", check.Info, z.name, "Règles de pare-feu Cloudflare", summary)
	for _, h := range z.hosts {
		if p, ok := z.res.Proxied[h]; ok && !p {
			continue // hors proxy : les règles ne s'appliquent pas
		}
		z.res.Notes[h] = "Cloudflare : " + summary
		if len(geo.Allowed)+len(geo.Blocked) > 0 {
			z.res.Geo[h] = geo
		}
	}
}

// countries : pays laissés passer (« not … in {…} » d'une règle de blocage) et
// pays visés (« … in {…} ») d'une expression.
func countries(expr string) (allowed, blocked []string) {
	for _, m := range countrySet.FindAllStringSubmatch(expr, -1) {
		for _, q := range quoted.FindAllStringSubmatch(m[2], -1) {
			if m[1] != "" {
				allowed = append(allowed, strings.ToUpper(q[1]))
			} else {
				blocked = append(blocked, strings.ToUpper(q[1]))
			}
		}
	}
	for _, m := range countryEq.FindAllStringSubmatch(expr, -1) {
		if (m[1] != "") != (m[2] == "ne" || m[2] == "!=") {
			allowed = append(allowed, strings.ToUpper(m[3]))
		} else {
			blocked = append(blocked, strings.ToUpper(m[3]))
		}
	}
	return
}

var (
	countrySet = regexp.MustCompile(`(not\s+|!\s*)?\(?\s*ip\.(?:geoip|src)\.country\s+in\s+\{([^}]*)\}`)
	countryEq  = regexp.MustCompile(`(not\s+|!\s*)?\(?\s*ip\.(?:geoip|src)\.country\s+(eq|==|ne|!=)\s+"([A-Za-z0-9]{2})"`)
	quoted     = regexp.MustCompile(`"([^"]*)"`)
	botField   = regexp.MustCompile(`(not\s+|!\s*)?\(?\s*cf\.(client\.bot|verified_bot_category)\b`)
	uaField    = regexp.MustCompile(`http\.user_agent\s+(?:contains|eq|==|matches|~|wildcard|strict wildcard)\s+"([^"]*)"`)
)

// summarize décrit une règle sans moteur d'expression : pays, robots et user
// agents visés, puis action et description. Une expression plus riche n'est
// résumée que par ces fragments : c'est une lecture, pas une évaluation.
func summarize(action, expr, desc string) []string {
	var out []string
	block := action == "block"
	var in, notIn []string
	for _, m := range countrySet.FindAllStringSubmatch(expr, -1) {
		var cs []string
		for _, q := range quoted.FindAllStringSubmatch(m[2], -1) {
			cs = append(cs, strings.ToUpper(q[1]))
		}
		if m[1] != "" {
			notIn = append(notIn, cs...)
		} else {
			in = append(in, cs...)
		}
	}
	for _, m := range countryEq.FindAllStringSubmatch(expr, -1) {
		neg := (m[1] != "") != (m[2] == "ne" || m[2] == "!=")
		if neg {
			notIn = append(notIn, strings.ToUpper(m[3]))
		} else {
			in = append(in, strings.ToUpper(m[3]))
		}
	}
	switch {
	case len(notIn) > 0 && block:
		out = append(out, "pays autorisés "+strings.Join(notIn, ", "))
	case len(notIn) > 0:
		out = append(out, "pays hors "+strings.Join(notIn, ", ")+" : "+action)
	}
	switch {
	case len(in) > 0 && block:
		out = append(out, "pays bloqués "+strings.Join(in, ", "))
	case len(in) > 0:
		out = append(out, "pays "+strings.Join(in, ", ")+" : "+action)
	}
	if m := botField.FindStringSubmatch(expr); m != nil {
		what := "robots vérifiés"
		if m[1] != "" {
			what = "robots non vérifiés"
		}
		if block {
			out = append(out, what+" bloqués")
		} else {
			out = append(out, what+" : "+action)
		}
	}
	var uas []string
	for _, m := range uaField.FindAllStringSubmatch(expr, -1) {
		uas = append(uas, `"`+m[1]+`"`)
	}
	if len(uas) > 0 {
		out = append(out, "user agents "+strings.Join(uas, ", ")+" : "+action)
	}
	name := desc
	if name == "" {
		name = "sans description"
	}
	out = append(out, fmt.Sprintf("règle %q (%s)", name, action))
	return out
}

// clip borne une preuve à 300 caractères.
func clip(s string) string {
	r := []rune(s)
	if len(r) <= 300 {
		return s
	}
	return string(r[:299]) + "…"
}
