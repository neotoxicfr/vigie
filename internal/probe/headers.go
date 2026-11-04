package probe

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
)

// Sévérités calquées sur les pénalités de Mozilla HTTP Observatory (v2) :
// −20/−25 → moyen, −5/−10 → faible, 0 → info.

const (
	hstsMin     = 15552000 // 6 mois : seuil Observatory
	hstsPreload = 31536000 // 1 an : exigence de hstspreload.org
)

func (p *prober) hsts(h http.Header) {
	v := h.Get("Strict-Transport-Security")
	if v == "" {
		p.add("http.hsts.absent", check.Medium, "En-tête HSTS absent", "")
		return
	}
	maxAge, sub, preload := -1, false, false
	for _, d := range strings.Split(v, ";") {
		d = strings.TrimSpace(d)
		name, val, _ := strings.Cut(d, "=")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "max-age":
			if n, err := strconv.Atoi(strings.Trim(strings.TrimSpace(val), `"`)); err == nil {
				maxAge = n
			}
		case "includesubdomains":
			sub = true
		case "preload":
			preload = true
		}
	}
	switch {
	case maxAge < 0:
		p.add("http.hsts.absent", check.Medium, "En-tête HSTS invalide (max-age illisible)", v)
		return
	case maxAge == 0:
		p.add("http.hsts.absent", check.Medium, "HSTS désactivé (max-age=0)", "max-age=0")
		return
	case maxAge < hstsMin:
		p.add("http.hsts.short", check.Low, "HSTS trop court (moins de 6 mois)", v)
	}
	if !sub {
		// Observatory ne pénalise pas ; OWASP le recommande. Souvent un choix assumé.
		p.add("http.hsts.no-subdomains", check.Info, "HSTS sans includeSubDomains", v)
	}
	if sub && preload && maxAge >= hstsPreload {
		p.add("http.hsts.preload-ready", check.Info, "HSTS conforme aux exigences de préchargement", v)
	}
}

func (p *prober) headers(h http.Header) {
	// CSP, X-Frame-Options et Permissions-Policy ne s'appliquent qu'aux documents :
	// sur un « OK » en texte ou du JSON, leur absence ne protège ni n'expose rien.
	doc := isDocument(h)
	if doc {
		frameAncestors := p.csp(h.Values("Content-Security-Policy"))
		if !frameAncestors && h.Get("X-Frame-Options") == "" {
			p.add("http.xfo.absent", check.Medium, "Protection contre l'inclusion en cadre absente", "ni X-Frame-Options ni frame-ancestors")
		}
	}
	if !strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		p.add("http.nosniff.absent", check.Low, "X-Content-Type-Options: nosniff absent", h.Get("X-Content-Type-Options"))
	}
	if rp := referrer(h.Values("Referrer-Policy")); rp == "" {
		// Observatory : 0 (le défaut des navigateurs est strict-origin-when-cross-origin).
		p.add("http.referrer.absent", check.Info, "Referrer-Policy absent", "")
	} else if rp == "unsafe-url" || rp == "no-referrer-when-downgrade" {
		p.add("http.referrer.unsafe", check.Low, "Referrer-Policy laisse fuir l'URL complète", "Referrer-Policy: "+rp)
	}
	if doc && h.Get("Permissions-Policy") == "" && h.Get("Feature-Policy") == "" {
		p.add("http.permissions.absent", check.Low, "Permissions-Policy absent", "")
	}
	if h.Get("Cross-Origin-Opener-Policy") == "" {
		p.add("http.coop.absent", check.Info, "Cross-Origin-Opener-Policy absent", "")
	}
	if h.Get("Cross-Origin-Resource-Policy") == "" {
		p.add("http.corp.absent", check.Info, "Cross-Origin-Resource-Policy absent", "")
	}
}

// referrer : dernière valeur reconnue, comme les navigateurs.
func referrer(vals []string) string {
	known := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "origin": true,
		"origin-when-cross-origin": true, "same-origin": true, "strict-origin": true,
		"strict-origin-when-cross-origin": true, "unsafe-url": true}
	out := ""
	for _, v := range vals {
		for _, t := range strings.Split(v, ",") {
			if t = strings.ToLower(strings.TrimSpace(t)); known[t] {
				out = t
			}
		}
	}
	return out
}

type cspIssue struct {
	id    string
	sev   check.Severity
	title string
}

var (
	cspInline = cspIssue{"http.csp.unsafe-inline", check.Medium, "CSP autorise les scripts en ligne (unsafe-inline)"}
	cspEval   = cspIssue{"http.csp.unsafe-eval", check.Low, "CSP autorise eval (unsafe-eval)"}
	cspWild   = cspIssue{"http.csp.wildcard", check.Medium, "CSP autorise des scripts de n'importe quelle origine"}
	// Fréquent quand le proxy ne pose que frame-ancestors : la CSP existe mais ne limite pas les scripts.
	cspNoScript = cspIssue{"http.csp.no-script-src", check.Medium, "CSP sans default-src ni script-src : les scripts ne sont pas restreints"}
)

// csp analyse les politiques appliquées (Report-Only ignoré). Les navigateurs
// appliquent toutes les politiques : un défaut compte s'il est dans chacune.
// Renvoie vrai si frame-ancestors est posé.
func (p *prober) csp(policies []string) (frameAncestors bool) {
	if len(policies) == 0 {
		p.add("http.csp.absent", check.Medium, "Content-Security-Policy absent", "")
		return false
	}
	var common map[cspIssue]bool
	for _, pol := range policies {
		dirs := map[string][]string{}
		for _, d := range strings.Split(pol, ";") {
			f := strings.Fields(strings.ToLower(d))
			if len(f) > 0 {
				if _, dup := dirs[f[0]]; !dup {
					dirs[f[0]] = f[1:]
				}
			}
		}
		if _, ok := dirs["frame-ancestors"]; ok {
			frameAncestors = true
		}
		script, ok := dirs["script-src"]
		if !ok {
			script, ok = dirs["default-src"]
		}
		found := map[cspIssue]bool{}
		if !ok {
			found[cspNoScript] = true // CSP sans default-src ni script-src : scripts non restreints
		}
		safe, dynamic := false, false
		for _, s := range script {
			if strings.HasPrefix(s, "'nonce-") || strings.HasPrefix(s, "'sha") || s == "'strict-dynamic'" {
				safe = true // unsafe-inline est alors ignoré par les navigateurs récents
			}
			if s == "'strict-dynamic'" {
				dynamic = true // *, http: et https: sont alors ignorés (repli CSP2 de Google)
			}
		}
		for _, s := range script {
			switch s {
			case "'unsafe-inline'":
				if !safe {
					found[cspInline] = true
				}
			case "'unsafe-eval'":
				found[cspEval] = true
			case "*", "http:", "https:":
				if !dynamic {
					found[cspWild] = true
				}
			case "data:":
				found[cspWild] = true
			}
		}
		obj, ok := dirs["object-src"]
		if !ok {
			obj = dirs["default-src"]
		}
		for _, s := range obj {
			if s == "*" || s == "http:" || s == "https:" {
				found[cspWild] = true
			}
		}
		if common == nil {
			common = found
		} else {
			for k := range common {
				if !found[k] {
					delete(common, k)
				}
			}
		}
	}
	ev := strings.Join(policies, " | ")
	for _, i := range []cspIssue{cspInline, cspEval, cspWild, cspNoScript} {
		if common[i] {
			p.add(i.id, i.sev, i.title, ev)
		}
	}
	if !frameAncestors {
		p.add("http.csp.no-frame-ancestors", check.Info, "CSP sans frame-ancestors", ev)
	}
	return frameAncestors
}

var sessionLike = regexp.MustCompile(`(?i)sess|sid|auth|token|jwt|login|remember|csrf|xsrf`)
var cookieName = regexp.MustCompile(`[^a-z0-9_.-]`)

func (p *prober) cookies(chain []*response) {
	seen := map[string]bool{}
	for _, r := range chain {
		https := r.url.Scheme == "https"
		for _, line := range r.header.Values("Set-Cookie") {
			c, err := http.ParseSetCookie(line)
			if err != nil || seen[c.Name] {
				continue
			}
			seen[c.Name] = true
			if c.MaxAge < 0 || (!c.Expires.IsZero() && c.Expires.Before(time.Now())) {
				continue // cookie d'effacement
			}
			id := cookieName.ReplaceAllString(strings.ToLower(c.Name), "_")
			ev := describeCookie(c)
			if https && !c.Secure {
				p.add("http.cookie.no-secure."+id, check.Medium, "Cookie sans Secure : "+c.Name, ev)
			}
			if !c.HttpOnly {
				// Observatory pénalise lourdement un cookie de session lisible par JS ; les autres moins.
				sev := check.Low
				if sessionLike.MatchString(c.Name) {
					sev = check.Medium
				}
				p.add("http.cookie.no-httponly."+id, sev, "Cookie sans HttpOnly : "+c.Name, ev)
			}
			switch c.SameSite {
			case 0, http.SameSiteDefaultMode:
				// Lax par défaut chez Chromium, pas partout : à poser explicitement.
				p.add("http.cookie.no-samesite."+id, check.Low, "Cookie sans SameSite : "+c.Name, ev)
			case http.SameSiteNoneMode:
				p.add("http.cookie.samesite-none."+id, check.Info, "Cookie envoyé en intersite (SameSite=None) : "+c.Name, ev)
			}
			// Préfixe mal respecté : le navigateur rejette le cookie (fonction cassée ou protection illusoire).
			bad := (strings.HasPrefix(c.Name, "__Secure-") && !c.Secure) ||
				(strings.HasPrefix(c.Name, "__Host-") && (!c.Secure || c.Domain != "" || c.Path != "/"))
			if bad {
				p.add("http.cookie.prefix-invalid."+id, check.Medium, "Préfixe de cookie non respecté : "+c.Name, ev)
			}
		}
	}
}

// describeCookie : attributs seulement, jamais la valeur.
func describeCookie(c *http.Cookie) string {
	parts := []string{c.Name}
	if c.Domain != "" {
		parts = append(parts, "Domain="+c.Domain)
	}
	if c.Path != "" {
		parts = append(parts, "Path="+c.Path)
	}
	if c.Secure {
		parts = append(parts, "Secure")
	}
	if c.HttpOnly {
		parts = append(parts, "HttpOnly")
	}
	switch c.SameSite {
	case http.SameSiteLaxMode:
		parts = append(parts, "SameSite=Lax")
	case http.SameSiteStrictMode:
		parts = append(parts, "SameSite=Strict")
	case http.SameSiteNoneMode:
		parts = append(parts, "SameSite=None")
	}
	return strings.Join(parts, "; ")
}

var versionRe = regexp.MustCompile(`\d+\.\d+`)

// serverVersion : une version exposée aide à cibler une faille connue (faible).
func (p *prober) serverVersion(h http.Header) {
	var ev []string
	for _, k := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Runtime-Version"} {
		if v := h.Get(k); v != "" && (versionRe.MatchString(v) || strings.HasPrefix(k, "X-AspNet")) {
			ev = append(ev, k+": "+v)
		}
	}
	if len(ev) > 0 {
		p.add("http.server.version", check.Low, "Version logicielle exposée dans les en-têtes", strings.Join(ev, ", "))
	}
}

// cache : une réponse qui pose un cookie sans no-store/private peut être
// gardée par un cache partagé et servie à d'autres (fuite de session).
func (p *prober) cache(r *response) {
	if len(r.header.Values("Set-Cookie")) == 0 {
		return
	}
	cc := strings.ToLower(strings.Join(r.header.Values("Cache-Control"), ","))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return
	}
	p.add("http.cache.private-cacheable", check.Low, "Réponse avec cookie potentiellement mise en cache partagé", "Cache-Control: "+cc)
}

// isDocument : réponse qu'un navigateur affiche comme une page (HTML, XHTML,
// SVG), ou sans type déclaré, qu'il devinerait.
func isDocument(h http.Header) bool {
	ct := strings.ToLower(h.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "html") || strings.Contains(ct, "svg")
}
