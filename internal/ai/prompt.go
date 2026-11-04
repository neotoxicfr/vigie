package ai

import (
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

// System est fixe d'une analyse à l'autre (cache de prompt).
const System = `Tu es un expert en sécurité des infrastructures web auto-hébergées (reverse proxys Traefik, Caddy, nginx, Nginx Proxy Manager ; portails d'authentification ; CDN ; TLS ; DNS et courrier).
On te donne les constats d'un passage de vigie, un outil d'audit passif, et la chaîne de middlewares de chaque route. Chaque ligne est un écart (contrôle et cible), avec les points de vue qui l'ont mesuré.

La demande est découpée en sections ; respecte leur rôle :
- « Écarts ouverts » : la seule matière de tes sections 2 à 4.
- « Faits mesurés » : informations (ports, origine, sorties, exposition) qui éclairent le risque ; pas des écarts.
- « Résolus » : ce qui a disparu depuis le passage précédent ; à citer dans la synthèse seulement.
- « Écarts assumés » et « Contrôles exclus » : déjà tranchés par l'administrateur, avec leur raison. N'en reparle nulle part (ni priorités, ni hygiène, ni faux positifs, ni limites), et ne propose aucun correctif pour eux. Seule exception : un écart ouvert qui rend l'un d'eux dangereux ; dis-le alors en une ligne dans les priorités, en citant la raison donnée.

Ce que tu dois savoir pour lire les constats :
- « vue » est le point de vue de la mesure : public (chemin d'un visiteur, CDN compris, même en DNS divisé), dns (contrôles DNS), origine (adresse publique du serveur, sans CDN), interne (proxy joint directement), inconnu (exposition DÉDUITE de la configuration, jamais mesurée), config (analyse statique). Tout autre nom est une sortie par proxy (VPN, autre site) : la vue réelle de l'extérieur, ports de l'origine compris ; son IP et son pays sont dans le constat proxy.exit.
- « privilégié » signifie que la machine de vigie passe des contrôles d'accès qu'un inconnu ne passerait pas : la mesure ne montre pas ce que voit un visiteur quelconque. Cette dispense (réseau local, IP de l'administrateur, constat access.privileged) est configurée exprès : présente-la comme une limite de mesure, jamais comme un défaut.
- http.auth.session-required : le point de vue n'a reçu que la réponse du contrôle d'accès ; rien n'est dit des en-têtes de l'application depuis ce point de vue.
- « état » vaut nouveau, inchangé ou résolu par rapport au passage précédent.

Réponds en français, en Markdown, en deux pages environ, avec ces sections :
1. **Synthèse** : trois à cinq phrases sur l'état général et ce qui a changé.
2. **À traiter en priorité** : au plus sept écarts réels, classés par risque concret (exploitabilité, exposition à un inconnu). Pour chacun : la cible, pourquoi c'est un problème ici en deux ou trois phrases, puis le correctif précis pour le proxy concerné. Un extrait de configuration seulement si le correctif n'est pas évident, et court. Regroupe en un seul point les écarts de même cause sur plusieurs hôtes.
3. **Hygiène** : un tableau (cible, écart, correctif en une ligne) pour les écarts mineurs restants ; regroupe les hôtes qui partagent le même écart.
4. **Probables faux positifs ou choix à assumer** : parmi les écarts ouverts seulement, une ligne par point, avec la raison à noter.
5. **Ce que l'audit ne voit pas** : limites liées aux points de vue privilégiés ou aux informations manquantes, une ligne chacune ; ce qui reste à vérifier va ici, pas dans les priorités.

Ne propose jamais un correctif qui contredit un choix déjà tranché par l'administrateur (section dédiée de la demande) ; si un risque grave le justifie, dis-le explicitement comme une remise en cause.
Ne recommande pas d'ajouter une CSP par le reverse proxy (middleware headers de Traefik, add_header de nginx) à une application qui pose déjà la sienne : avec Traefik, l'en-tête du middleware remplace celui de l'application, il ne s'y combine pas, et casse les applications qui ont besoin de leur propre politique (Collabora, Nextcloud…). Propose de corriger la CSP côté application, ou une politique propre à la route quand l'application n'en pose aucune.

Écris toutes les sections, même brèves : mieux vaut un point de moins que finir coupé. Propose le correctif proportionné, pas le plus lourd possible.

Règles : n'invente aucun constat ni aucune version ; appuie-toi seulement sur les données fournies ; si une information manque, dis-le. Les noms d'hôte et adresses peuvent être masqués (host-001, domain-001, ip-001) : garde ces jetons tels quels dans ta réponse.`

// Input : ce qu'une analyse reçoit d'un passage.
type Input struct {
	Run      store.Run
	First    bool              // aucun passage terminé avant celui-ci
	Decided  string            // choix déjà tranchés (réglage ai.context)
	Excluded map[string]string // contrôle exclu partout → raison
	Deltas   []store.Delta
	Routes   []source.Route
	Mask     bool
}

// issue : un écart (contrôle + cible) et tous les points de vue qui l'ont vu.
type issue struct {
	d        store.Delta // le plus grave, preuve d'une vue non privilégiée de préférence
	vantages []string
	privOnly bool
	isNew    bool // nouveau depuis au moins une vue
}

// Build prépare la demande, découpée par rôle : écarts ouverts, faits mesurés,
// résolus, puis ce que l'administrateur a déjà tranché, à ne pas re-signaler.
// Avec Mask, noms d'hôte, domaines et IP deviennent des jetons, et unmask les
// rétablit dans la réponse.
func Build(in Input) (prompt string, unmask func(string) string) {
	var b strings.Builder
	fmt.Fprintf(&b, "Passage du %s, statut %s.\n", in.Run.Started.Local().Format("02/01/2006 15:04"), in.Run.Status)
	if in.First {
		b.WriteString("Premier passage terminé : aucun précédent, donc tous les constats sont « nouveau » par construction.\n")
	}
	if in.Run.Note != "" {
		fmt.Fprintf(&b, "Note du passage : %s\n", in.Run.Note)
	}
	if d := strings.TrimSpace(in.Decided); d != "" {
		b.WriteString("\n## Choix déjà tranchés par l'administrateur (à respecter)\n" + d + "\n")
	}
	b.WriteString("\n## Routes et chaînes de middlewares\n")
	for _, r := range in.Routes {
		var mws []string
		for _, m := range r.Middlewares {
			mws = append(mws, m.Name+" ("+string(m.Kind)+")")
		}
		fmt.Fprintf(&b, "- %s [%s] hôtes %s chemins %s ports %v : %s\n", r.Name, r.Source, strings.Join(r.Hosts, ","),
			strings.Join(r.Paths, ","), r.Ports, strings.Join(mws, " → "))
	}

	// Regroupement par écart, dans l'ordre des deltas (sévérité décroissante).
	var order []string
	byKey := map[string]*issue{}
	for _, d := range in.Deltas {
		k := d.IssueKey()
		if d.State == store.Resolved {
			k += "/résolu"
		}
		is := byKey[k]
		if is == nil {
			is = &issue{d: d, privOnly: true}
			byKey[k] = is
			order = append(order, k)
		}
		if !slices.Contains(is.vantages, d.Vantage) {
			is.vantages = append(is.vantages, d.Vantage)
		}
		if d.Severity > is.d.Severity || (is.d.Privileged && !d.Privileged && d.Severity == is.d.Severity) {
			acc := is.d.Accepted
			is.d = d
			if is.d.Accepted == nil {
				is.d.Accepted = acc
			}
		}
		is.isNew = is.isNew || d.State == store.New
		is.privOnly = is.privOnly && d.Privileged
	}
	for _, is := range byKey {
		if is.isNew {
			is.d.State = store.New
		}
	}
	var open, facts, resolved, accepted []*issue
	for _, k := range order {
		is := byKey[k]
		switch d := is.d; {
		case d.Accepted != nil:
			if d.State != store.Resolved {
				accepted = append(accepted, is)
			}
		case d.State == store.Resolved:
			if d.Severity > 0 {
				resolved = append(resolved, is)
			}
		case d.Severity > 0:
			open = append(open, is)
		case infoKept(d.Check):
			facts = append(facts, is)
		}
	}
	// section : les écarts de même contrôle, titre, état et points de vue sur
	// plusieurs cibles tiennent sur une ligne (même cause, même correctif).
	section := func(title string, list []*issue, evidence bool) {
		b.WriteString("\n## " + title + "\n")
		if len(list) == 0 {
			b.WriteString("(aucun)\n")
		}
		var gorder []string
		groups := map[string][]*issue{}
		for _, is := range list {
			k := strings.Join([]string{is.d.Check, is.d.Title, is.d.Severity.String(), string(is.d.State),
				strings.Join(is.vantages, ","), strconv.FormatBool(is.privOnly)}, "\x00")
			if _, ok := groups[k]; !ok {
				gorder = append(gorder, k)
			}
			groups[k] = append(groups[k], is)
		}
		for i, k := range gorder {
			if i == 1500 { // borne la taille de la demande
				b.WriteString("- … (liste tronquée)\n")
				break
			}
			g := groups[k]
			d := g[0].d
			var targets []string
			sameEvidence := true
			for _, is := range g {
				targets = append(targets, is.d.Target)
				sameEvidence = sameEvidence && is.d.Evidence == d.Evidence
			}
			flags := []string{"sévérité " + d.Severity.String(), "état " + string(d.State), "vues " + strings.Join(g[0].vantages, ", ")}
			if g[0].privOnly && d.Vantage != "config" && d.Vantage != "inconnu" {
				flags = append(flags, "vu seulement depuis des points de vue privilégiés")
			}
			who := strings.Join(targets, ", ")
			if len(targets) > 1 {
				who = strconv.Itoa(len(targets)) + " cibles : " + who
			}
			fmt.Fprintf(&b, "- [%s] %s — %s (%s)", d.Check, who, d.Title, strings.Join(flags, ", "))
			switch {
			case !evidence || d.Evidence == "":
			case sameEvidence:
				fmt.Fprintf(&b, " preuve : %s", d.Evidence)
			case len(g) == 1:
				fmt.Fprintf(&b, " preuve : %s", d.Evidence)
			default:
				for _, is := range g {
					fmt.Fprintf(&b, "\n  - %s : %s", is.d.Target, is.d.Evidence)
				}
			}
			b.WriteString("\n")
		}
	}
	section("Écarts ouverts (à analyser)", open, true)
	section("Faits mesurés (information)", facts, true)
	section("Résolus depuis le passage précédent", resolved, false)

	// Assumés : regroupés par contrôle et raison, cibles à la suite.
	b.WriteString("\n## Écarts assumés par l'administrateur (déjà tranchés : ne pas re-signaler)\n")
	type group struct{ check, note string }
	var gorder []group
	targets := map[group][]string{}
	for _, is := range accepted {
		g := group{is.d.Check, is.d.Accepted.Note}
		if _, ok := targets[g]; !ok {
			gorder = append(gorder, g)
		}
		if !slices.Contains(targets[g], is.d.Target) {
			targets[g] = append(targets[g], is.d.Target)
		}
	}
	if len(gorder) == 0 {
		b.WriteString("(aucun)\n")
	}
	for _, g := range gorder {
		fmt.Fprintf(&b, "- [%s] %s — raison : %s\n", g.check, strings.Join(targets[g], ", "), g.note)
	}
	b.WriteString("\n## Contrôles exclus partout (déjà tranchés : ne pas re-signaler)\n")
	var ex []string
	for c := range in.Excluded {
		ex = append(ex, c)
	}
	sort.Strings(ex)
	if len(ex) == 0 {
		b.WriteString("(aucun)\n")
	}
	for _, c := range ex {
		if why := in.Excluded[c]; why != "" {
			fmt.Fprintf(&b, "- [%s] — raison : %s\n", c, why)
		} else {
			fmt.Fprintf(&b, "- [%s]\n", c)
		}
	}
	prompt = b.String()
	if !in.Mask {
		return prompt, func(s string) string { return s }
	}
	return masker(prompt, in.Routes, in.Deltas)
}

var (
	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// Candidat IPv6 : au moins deux « : », y compris en tête (« ::1 », « ::ffff:192.0.2.1 »).
	ipv6Re = regexp.MustCompile(`[0-9A-Fa-f:]*:[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*`)
	// Candidat FQDN : labels RFC 1123 (plus « _ » pour _dmarc…), TLD alphabétique d'au moins 2 lettres.
	fqdnRe  = regexp.MustCompile(`(?i)\b(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,}\b`)
	tokenRe = regexp.MustCompile(`\b(?:host|domain|ip)-\d{3}\b`)
)

func masker(text string, routes []source.Route, ds []store.Delta) (string, func(string) string) {
	hosts := map[string]bool{}
	for _, r := range routes {
		for _, h := range r.Hosts {
			hosts[strings.ToLower(h)] = true
		}
	}
	for _, d := range ds {
		t := d.Target
		if i := strings.IndexByte(t, '/'); i >= 0 {
			t = t[:i]
		}
		if h, _, err := net.SplitHostPort(t); err == nil {
			t = h
		}
		hosts[strings.ToLower(t)] = true
	}
	toTok := map[string]string{}
	fromTok := map[string]string{}
	add := func(v, kind string) {
		if v == "" || toTok[v] != "" {
			return
		}
		tok := fmt.Sprintf("%s-%03d", kind, len(toTok)+1)
		toTok[v], fromTok[tok] = tok, v
	}
	var names []string
	for h := range hosts {
		if net.ParseIP(h) != nil {
			add(h, "ip")
			continue
		}
		names = append(names, h)
	}
	sort.Strings(names)
	domains := map[string]bool{}
	for _, h := range names {
		add(h, "host")
		if d, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
			domains[d] = true
		}
	}
	var ds2 []string
	for d := range domains {
		ds2 = append(ds2, d)
	}
	sort.Strings(ds2)
	for _, d := range ds2 {
		add(d, "domain")
	}
	// Identifiants de contrôle et noms de middleware ou de route : jamais pris pour des noms d'hôte.
	skip := map[string]bool{}
	for _, d := range ds {
		skip[d.Check] = true
	}
	for _, r := range routes {
		skip[r.Name] = true
		for _, m := range r.Middlewares {
			skip[m.Name] = true
		}
	}
	// nameKind rend le genre de jeton d'un nom, ou "" s'il ne faut pas le masquer.
	nameKind := func(name string) string {
		if toTok[name] != "" {
			return "known"
		}
		for d := range domains {
			if strings.HasSuffix(name, "."+d) { // sous-domaine d'un domaine connu : masqué entier
				return "host"
			}
		}
		suffix, icann := publicsuffix.PublicSuffix(name)
		if !icann && !strings.Contains(suffix, ".") { // TLD inexistant : « http.hsts.absent »
			return ""
		}
		if d, err := publicsuffix.EffectiveTLDPlusOne(name); err == nil && d == name {
			return "domain"
		}
		return "host"
	}
	sub := func(v, kind string) string {
		add(v, kind)
		return toTok[v]
	}
	masked := ipv6Re.ReplaceAllStringFunc(text, func(m string) string {
		core := strings.TrimRight(m, ".")
		if strings.HasSuffix(core, ":") && !strings.HasSuffix(core, "::") {
			core = core[:len(core)-1]
		}
		if net.ParseIP(core) == nil {
			return m
		}
		return sub(strings.ToLower(core), "ip") + m[len(core):]
	})
	masked = ipv4Re.ReplaceAllStringFunc(masked, func(m string) string {
		if net.ParseIP(m) == nil {
			return m
		}
		return sub(m, "ip")
	})
	masked = fqdnRe.ReplaceAllStringFunc(masked, func(m string) string {
		if skip[m] {
			return m
		}
		name := strings.ToLower(m)
		if k := nameKind(name); k != "" {
			if k == "known" {
				return toTok[name]
			}
			return sub(name, k)
		}
		return m
	})
	return masked, func(s string) string {
		return tokenRe.ReplaceAllStringFunc(s, func(t string) string {
			if v, ok := fromTok[t]; ok {
				return v
			}
			return t
		})
	}
}

// infoKept : constats d'information qui renseignent l'analyse (ce qui est
// ouvert, comment l'origine et les sorties se comportent).
func infoKept(c string) bool {
	if c == "chain.exposure" {
		return true
	}
	for _, p := range []string{"port.", "origin.", "proxy.", "geo.", "exposure.", "cf.aop.", "cf.waf.", "access.", "http.auth.", "dns.open-resolver"} {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}
