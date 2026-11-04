// Package kb associe à chaque identifiant de constat (check.Finding.Check) une explication du risque
// et des correctifs prêts à copier pour les proxys courants.
package kb

import (
	"fmt"
	"strings"
)

// Fix est un correctif pour un proxy (traefik, caddy, nginx, npm, cloudflare) ou « général ».
type Fix struct{ Proxy, Label, Code string }

// Entry : Risk dit en 2 à 4 phrases pourquoi c'est un risque ici.
type Entry struct {
	Title, Risk string
	Fixes       []Fix
	Refs        []string
}

var tables = []map[string]Entry{httpEntries, tlsEntries, dnsEntries, miscEntries}

// Lookup cherche d'abord l'identifiant exact, puis le plus long préfixe se terminant par « . »
// (familles dynamiques : http.cookie.no-secure.<nom>, tls.cert.lint.<lint>, port.risky.<service>…).
func Lookup(check string) (Entry, bool) {
	for p := check; ; {
		for _, t := range tables {
			if e, ok := t[p]; ok {
				return e, true
			}
		}
		i := strings.LastIndex(strings.TrimSuffix(p, "."), ".")
		if i < 0 {
			return Entry{}, false
		}
		p = p[:i+1]
	}
}

// Dans le code des correctifs, ¤ vaut une apostrophe inversée (les règles Traefik en contiennent).
func fx(proxy, label, code string) Fix {
	return Fix{proxy, label, strings.ReplaceAll(code, "¤", "`")}
}

func e(title, risk string, refs []string, fixes ...Fix) Entry {
	return Entry{Title: title, Risk: risk, Fixes: fixes, Refs: refs}
}

// hdr donne les cinq façons de poser un en-tête de réponse. id nomme le middleware Traefik.
func hdr(id, name, value string) []Fix {
	return []Fix{
		fx("traefik", "Labels Docker", fmt.Sprintf("traefik.http.middlewares.%s.headers.customresponseheaders.%s=%s\ntraefik.http.routers.<routeur>.middlewares=%s", id, name, value, id)),
		fx("traefik", "Middleware (fichier dynamique)", fmt.Sprintf("http:\n  middlewares:\n    %s:\n      headers:\n        customResponseHeaders:\n          %s: \"%s\"", id, name, value)),
		fx("caddy", "Caddyfile, dans le bloc du site", fmt.Sprintf("header %s \"%s\"", name, value)),
		fx("nginx", "Bloc server (à répéter dans tout location qui pose ses propres add_header : ils ne sont pas hérités)", fmt.Sprintf("add_header %s \"%s\" always;", name, value)),
		fx("npm", "Proxy Host > Edit > Advanced > Custom Nginx Configuration (more_set_headers d'OpenResty : un add_header du serveur serait ignoré par le location / de NPM)", fmt.Sprintf("more_set_headers \"%s: %s\";", name, value)),
		fx("cloudflare", "Rules > Overview > Create rule > Response Header Transform Rule > Modify response header : Set static", fmt.Sprintf("Header name : %s ; Value : %s", name, value)),
	}
}

func cat(parts ...[]Fix) []Fix {
	var out []Fix
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func gen(label, code string) []Fix { return []Fix{{"général", label, code}} }

var (
	mdn  = "https://developer.mozilla.org/docs/Web/HTTP/Headers/"
	refs = func(s ...string) []string { return s }
)
