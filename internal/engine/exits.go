package engine

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neotoxicfr/vigie/internal/cdnprov"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/policy"
	"github.com/neotoxicfr/vigie/internal/scan"
	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/source"
)

// exitView : un point de vue par proxy et ce qu'on sait de sa sortie.
type exitView struct {
	v    scan.Vantage
	ip   netip.Addr      // IP de sortie vue par le CDN, si lue
	ip6  netip.Addr      // IPv6 de sortie, invalide si la sortie n'a pas d'IPv6
	loc  string          // pays de sortie selon le CDN
	priv map[string]bool // hôte → cette sortie passe des contrôles qu'un inconnu ne passerait pas
}

// exits prépare les sorties par proxy : IP et pays lus sur /cdn-cgi/trace d'un
// des hôtes audités (le CDN est déjà sur le chemin, aucun service tiers), puis
// privilège calculé avec cette IP. Une sortie injoignable est signalée et écartée.
func exits(ctx context.Context, g *scan.Guard, r config.Runtime, hosts []string, routes []source.Route, opts policy.Options) ([]exitView, []check.Finding, []string) {
	var out []exitView
	var fs []check.Finding
	var notes []string
	for _, pc := range r.Vantages.Proxies {
		u, err := url.Parse(pc.URL)
		if err != nil {
			continue // déjà refusé par la validation
		}
		if pc.Username != "" {
			u.User = url.User(pc.Username)
		}
		ev := exitView{v: scan.ProxyVantage(pc.Name, &scan.Proxy{URL: u, Password: settings.Secret(pc.PasswordFile)}), priv: map[string]bool{}}
		var lastErr error
		answered := false // la sortie a joint un hôte, qui n'expose pas /cdn-cgi/trace
		for i, h := range hosts {
			if i == 3 {
				break
			}
			ev.ip, ev.loc, lastErr = trace(ctx, g, ev.v, h, h)
			if lastErr == nil {
				// Même hôte par son adresse IPv6 publique : la sortie a-t-elle l'IPv6 ?
				for _, a := range lookupPublic(ctx, r.Scan.Resolver, h) {
					if a.Is6() {
						if ip, _, err := trace(ctx, g, ev.v, h, a.String()); err == nil && ip.Is6() {
							ev.ip6 = ip
						}
						break
					}
				}
				break
			}
			answered = answered || errors.Is(lastErr, errNoTrace)
		}
		if !ev.ip.IsValid() && answered {
			// Hôtes hors Cloudflare : la sortie mesure quand même, sans IP ni pays ;
			// ce qui exige de savoir qui elle est (privilège, exposition) est sauté.
			fs = append(fs, check.Finding{Check: "proxy.exit", Target: pc.Name, Vantage: pc.Name, Severity: check.Info,
				Title:    "Sortie « " + pc.Name + " » : IP inconnue",
				Evidence: "les hôtes audités ne donnent pas l'IP du visiteur (/cdn-cgi/trace, propre à Cloudflare) : mesures faites, mais ni liste blanche ni écart d'exposition jugés depuis cette sortie"})
			out = append(out, ev)
			continue
		}
		if !ev.ip.IsValid() {
			why := "aucun hôte à interroger"
			if lastErr != nil {
				why = lastErr.Error()
			}
			fs = append(fs, check.Finding{Check: "proxy.unreachable", Target: pc.Name, Vantage: pc.Name, Severity: check.Medium,
				Title: "Sortie « " + pc.Name + " » inutilisable : rien n'a été mesuré depuis elle", Evidence: trim(why)})
			notes = append(notes, "sortie "+pc.Name+" injoignable")
			continue
		}
		v6 := ", sans IPv6"
		if ev.ip6.IsValid() {
			v6 = ", IPv6 " + ev.ip6.String()
		}
		fs = append(fs, check.Finding{Check: "proxy.exit", Target: pc.Name, Vantage: pc.Name, Severity: check.Info,
			Title:    "Sortie « " + pc.Name + " » : " + ev.ip.String() + " (" + ev.loc + ")" + v6,
			Evidence: "IP et pays vus par le CDN ; les mesures « " + pc.Name + " » partent de là"})
		eo := opts
		eo.Egress = []netip.Addr{ev.ip}
		if ev.ip6.IsValid() {
			eo.Egress = append(eo.Egress, ev.ip6)
		}
		for _, rt := range routes {
			if p, _ := policy.Privileged(rt, eo); p {
				for _, h := range rt.Hosts {
					ev.priv[strings.ToLower(h)] = true
				}
			}
		}
		out = append(out, ev)
	}
	return out, fs, notes
}

var errNoTrace = errors.New("hôte hors Cloudflare")

// trace lit ip= et loc= sur https://hôte/cdn-cgi/trace à travers la sortie, en
// joignant dial (le nom de l'hôte ou une de ses adresses).
func trace(ctx context.Context, g *scan.Guard, v scan.Vantage, host, dial string) (netip.Addr, string, error) {
	tr := &http.Transport{
		DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return g.Dial(ctx, v, dial, 443) },
		TLSClientConfig:   &tls.Config{ServerName: host},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/cdn-cgi/trace", nil)
	if err != nil {
		return netip.Addr{}, "", err
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := c.Do(req)
	if err != nil {
		return netip.Addr{}, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, "", fmt.Errorf("%w : %s/cdn-cgi/trace : %s", errNoTrace, host, resp.Status)
	}
	ip, loc := parseTrace(io.LimitReader(resp.Body, 8<<10))
	if !ip.IsValid() {
		return ip, "", fmt.Errorf("%w : %s/cdn-cgi/trace : réponse sans ip", errNoTrace, host)
	}
	return ip, loc, nil
}

// parseTrace lit le format clé=valeur de /cdn-cgi/trace.
func parseTrace(r io.Reader) (netip.Addr, string) {
	var ip netip.Addr
	loc := "?"
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, val, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "ip":
			ip, _ = netip.ParseAddr(val)
		case "loc":
			loc = val
		}
	}
	return ip.Unmap(), loc
}

// classifyGeo remplace, pour chaque sortie, les pages de blocage du CDN par un
// jugement : blocage attendu (pays non autorisé) = géoblocage vérifié, un seul
// constat positif ; hôte joignable alors que le pays est bloqué = contournement ;
// blocage d'un pays autorisé = blocage inattendu.
func classifyGeo(fs []check.Finding, views []exitView, geo map[string]cdnprov.Geo) []check.Finding {
	byExit := map[string]exitView{}
	for _, ev := range views {
		byExit[ev.v.Name] = ev
	}
	type tally struct{ blocked, open map[string]bool }
	per := map[string]*tally{}
	kept := fs[:0]
	for _, f := range fs {
		ev, isExit := byExit[f.Vantage]
		if !isExit || !strings.HasPrefix(f.Check, "http.") {
			kept = append(kept, f)
			continue
		}
		t := per[ev.v.Name]
		if t == nil {
			t = &tally{blocked: map[string]bool{}, open: map[string]bool{}}
			per[ev.v.Name] = t
		}
		host := check.Unit(f.Target)
		switch f.Check {
		case "http.cdn-blocked":
			t.blocked[host] = true
			continue // remplacé par le jugement ci-dessous
		case "http.unreachable":
		default:
			t.open[host] = true
		}
		kept = append(kept, f)
	}
	for name, t := range per {
		ev := byExit[name]
		var verified, unknown, unexpected []string
		for h := range t.blocked {
			g, known := geo[h]
			switch {
			case !known:
				unknown = append(unknown, h)
			case g.Blocks(ev.loc):
				verified = append(verified, h)
			default:
				unexpected = append(unexpected, h)
			}
		}
		for h := range t.open {
			if g, known := geo[h]; known && g.Blocks(ev.loc) && !t.blocked[h] {
				kept = append(kept, check.Finding{Check: "geo.bypass", Target: h, Vantage: name, Severity: check.High,
					Title:    "Joignable depuis " + ev.loc + " malgré le géoblocage",
					Evidence: fmt.Sprintf("sortie %s (%s) ; pays autorisés : %s", name, ev.loc, strings.Join(g.Allowed, ", "))})
			}
		}
		sort.Strings(unexpected)
		for _, h := range unexpected {
			kept = append(kept, check.Finding{Check: "geo.unexpected-block", Target: h, Vantage: name, Severity: check.Medium,
				Title:    "Bloqué par le CDN depuis " + ev.loc + ", pourtant pays autorisé",
				Evidence: "sortie " + name + " : une autre règle (WAF, robots, réputation de l'IP) bloque ce visiteur"})
		}
		if n := len(verified); n > 0 {
			kept = append(kept, check.Finding{Check: "geo.verified", Target: name, Vantage: name, Severity: check.Info,
				Title:    fmt.Sprintf("Géoblocage vérifié depuis %s (%s) : %d hôte(s) bloqué(s) comme attendu", name, ev.loc, n),
				Evidence: "le CDN refuse ce pays avant d'atteindre l'origine ; c'est la preuve que la règle est active"})
		}
		if n := len(unknown); n > 0 {
			sort.Strings(unknown)
			kept = append(kept, check.Finding{Check: "http.cdn-blocked", Target: name, Vantage: name, Severity: check.Info,
				Title:    fmt.Sprintf("Bloqué par le CDN depuis %s (%s) : %d hôte(s)", name, ev.loc, n),
				Evidence: trim("règles du CDN non lues (Cloudflare non activé dans Réglages ?) : " + strings.Join(unknown, ", "))})
		}
	}
	return kept
}

var openness = map[string]int{policy.Public: 0, policy.PublicViaCDN: 1, policy.Auth: 2, policy.Blocked: 3}

// hostExposure : pour chaque hôte, l'exposition déduite la plus ouverte de ses routes.
func hostExposure(routes []source.Route, opts policy.Options) map[string]string {
	out := map[string]string{}
	for _, r := range routes {
		level, _ := policy.Exposure(r, opts)
		for _, h := range r.Hosts {
			h = strings.ToLower(h)
			if cur, ok := out[h]; !ok || openness[level] < openness[cur] {
				out[h] = level
			}
		}
	}
	return out
}

// Contrôles d'hygiène des en-têtes : leur risque suppose qu'un inconnu atteigne
// l'application. Derrière une authentification, il ne voit que le portail.
var hygiene = []string{"http.csp.", "http.xfo.", "http.nosniff.", "http.referrer.", "http.permissions.", "http.coop.",
	"http.corp.", "http.sri.", "http.mixed-content", "http.server.version", "http.cache.", "http.cookie.no-samesite.",
	"http.cookie.samesite-none.", "http.error.verbose", "http.method.trace", "http.compression."}

func isHygiene(id string) bool {
	for _, p := range hygiene {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

// judgeExposure confronte la déduction aux mesures des sorties non privilégiées,
// puis abaisse d'un cran l'hygiène des hôtes qu'un inconnu ne peut pas atteindre
// sans s'authentifier — sauf si une sortie a prouvé le contraire.
func judgeExposure(fs []check.Finding, views []exitView, exposure map[string]string) []check.Finding {
	stranger := map[string]bool{}
	for _, ev := range views {
		if len(ev.priv) == 0 && ev.ip.IsValid() {
			stranger[ev.v.Name] = true
		}
	}
	mismatch := map[string]bool{}
	var extra []check.Finding
	// Sortie refusée presque partout (403 hors page du CDN) : son IP est sans doute
	// bannie par un IPS (CrowdSec…) ; ses mesures ne valent pas celles d'un visiteur neuf.
	denied, seenAccess := map[string]int{}, map[string]int{}
	for _, f := range fs {
		if strings.HasPrefix(f.Check, "http.access.") {
			seenAccess[f.Vantage]++
			if f.Check == "http.access.denied" {
				denied[f.Vantage]++
			}
		}
	}
	banned := map[string]bool{}
	for v, n := range seenAccess {
		if n >= 5 && denied[v]*5 >= n*4 {
			banned[v] = true
			extra = append(extra, check.Finding{Check: "proxy.banned", Target: v, Vantage: v, Severity: check.Info,
				Title:    fmt.Sprintf("Sortie « %s » refusée sur %d/%d hôtes : IP probablement bannie par un IPS", v, denied[v], n),
				Evidence: "refus directs (403) hors page du CDN : souvent CrowdSec ou un WAF qui a banni cette IP ; la défense fonctionne, mais les mesures de cette sortie ne montrent pas ce que voit un visiteur neuf"})
		}
	}
	for _, f := range fs {
		// Un « ouvert » vaut même depuis une sortie bannie : la route échappe alors à l'IPS.
		if f.Check != "http.access.open" || !stranger[f.Vantage] {
			continue
		}
		h := check.Unit(f.Target)
		if lvl := exposure[h]; lvl == policy.Auth || lvl == policy.Blocked {
			if !mismatch[h] {
				extra = append(extra, check.Finding{Check: "exposure.mismatch", Target: h, Vantage: f.Vantage, Severity: check.High,
					Title:    "Ouvert à un inconnu alors que la configuration indique « " + lvl + " »",
					Evidence: trim("mesuré depuis la sortie " + f.Vantage + " : " + f.Evidence)})
			}
			mismatch[h] = true
		}
	}
	// Preuve positive : les hôtes déduits « auth » qu'une sortie inconnue voit bien
	// derrière l'authentification (pendant de geo.verified).
	gated, total := map[string]map[string]bool{}, map[string]map[string]bool{}
	for _, f := range fs {
		h := check.Unit(f.Target)
		if !stranger[f.Vantage] || banned[f.Vantage] || exposure[h] != policy.Auth || !strings.HasPrefix(f.Check, "http.access.") {
			continue
		}
		if total[f.Vantage] == nil {
			total[f.Vantage], gated[f.Vantage] = map[string]bool{}, map[string]bool{}
		}
		total[f.Vantage][h] = true
		if f.Check == "http.access.auth" {
			gated[f.Vantage][h] = true
		}
	}
	for _, ev := range views {
		v := ev.v.Name
		if n := len(gated[v]); n > 0 {
			extra = append(extra, check.Finding{Check: "exposure.verified", Target: v, Vantage: v, Severity: check.Info,
				Title:    fmt.Sprintf("Authentification exigée depuis %s : %d/%d hôtes protégés renvoient au contrôle d'accès", v, n, len(total[v])),
				Evidence: "mesuré depuis une sortie inconnue, ni en liste blanche ni bannie"})
		}
	}
	for i := range fs {
		f := &fs[i]
		h := check.Unit(f.Target)
		lvl := exposure[h]
		if mismatch[h] || (lvl != policy.Auth && lvl != policy.Blocked) || !isHygiene(f.Check) || f.Severity == check.Info {
			continue
		}
		f.Severity--
		f.Evidence = trim(f.Evidence + " — sévérité abaissée : un inconnu doit d'abord s'authentifier (exposition déduite « " + lvl + " »)")
	}
	return append(fs, extra...)
}

// originBypass joint chaque hôte directement sur chaque IP d'origine (SNI et Host
// corrects), en HTTPS puis HTTP, depuis chaque sortie dont l'IP est connue :
//   - sortie inconnue (ni liste blanche ni dispense) : l'origine doit refuser ; un
//     site servi échappe au CDN et à ses règles (origin.bypass) ;
//   - sortie en liste blanche : l'origine doit servir ses hôtes ; un refus casse
//     l'accès voulu (origin.allowed-refused).
//
// IPv4 et IPv6 sont comptés à part, et une famille non testée est dite.
func originBypass(ctx context.Context, g *scan.Guard, views []exitView, hosts []string, origins []netip.Addr) []check.Finding {
	var out []check.Finding
	for _, ev := range views {
		if !ev.ip.IsValid() {
			continue // sortie inconnue : on ne sait pas si elle est en liste blanche
		}
		allowed := len(ev.priv) > 0
		hs := hosts
		if allowed {
			hs = nil
			for _, h := range hosts {
				if ev.priv[h] {
					hs = append(hs, h)
				}
			}
		}
		type tally struct{ served, refused, redirected, closed, skipped int }
		fam := map[string]*tally{"IPv4": {}, "IPv6": {}}
		tested, present := map[string]bool{}, map[string]bool{}
		var mu sync.Mutex
		for _, ep := range originEndpoints(origins) {
			o, scheme, port := ep.addr, ep.scheme, ep.port
			f := family(o)
			present[f] = true
			if f == "IPv6" && !ev.ip6.IsValid() {
				continue // sortie sans IPv6 : l'échec ne dirait rien de l'origine
			}
			tested[f] = true
			t := fam[f]
			fails := 0 // par adresse et port : une v4 filtrée ne dit rien de la v6
			work := make(chan string)
			var wg sync.WaitGroup
			for i := 0; i < 2; i++ { // deux à la fois, comme le garde par hôte
				wg.Add(1)
				go func() {
					defer wg.Done()
					for h := range work {
						mu.Lock()
						shortcut := fails >= 3
						mu.Unlock()
						if shortcut {
							// shortcut: trois échecs de connexion d'affilée = filtrage réseau,
							// indépendant du nom d'hôte : inutile d'attendre les autres.
							mu.Lock()
							t.skipped++
							mu.Unlock()
							continue
						}
						status, loc, err := direct(ctx, g, ev.v, o, h, scheme, port)
						mu.Lock()
						switch {
						case errors.Is(err, errDial):
							t.closed++
							fails++
						case err != nil: // TCP joint, puis TLS ou HTTP refusé : l'origine répond
							t.closed++
							fails = 0
						case status == http.StatusForbidden || status == http.StatusMisdirectedRequest || status == http.StatusNotFound:
							t.refused++ // refus, ou aucune route pour ce nom : rien n'est servi
							fails = 0
						case scheme == "http" && status/100 == 3 && strings.HasPrefix(loc, "https://"):
							t.redirected++ // le visiteur repart en HTTPS par le nom, donc par le CDN
							fails = 0
						default:
							t.served++
							fails = 0
							if !allowed {
								out = append(out, check.Finding{Check: "origin.bypass", Target: h, Vantage: ev.v.Name, Severity: check.High,
									Title:    "Servi en direct sur l'IP d'origine : le CDN est contournable",
									Evidence: fmt.Sprintf("GET %s://%s/ via %s port %d depuis la sortie %s : statut %d", scheme, h, o, port, ev.v.Name, status)})
							}
						}
						mu.Unlock()
					}
				}()
			}
			for _, h := range hs {
				work <- h
			}
			close(work)
			wg.Wait()
		}
		var parts []string
		for _, f := range []string{"IPv4", "IPv6"} {
			t := fam[f]
			switch {
			case !present[f]:
				continue
			case !tested[f]:
				parts = append(parts, f+" non testée (sortie sans "+f+")")
				continue
			}
			p := fmt.Sprintf("%s : %d servis, %d refus, %d sans réponse", f, t.served, t.refused, t.closed)
			if t.redirected > 0 {
				p += fmt.Sprintf(", %d renvois vers HTTPS (port 80)", t.redirected)
			}
			if t.skipped > 0 {
				p += fmt.Sprintf(", %d non testés (adresse filtrée)", t.skipped)
			}
			parts = append(parts, p)
			if allowed && t.served == 0 && t.refused+t.closed > 0 {
				out = append(out, check.Finding{Check: "origin.allowed-refused", Target: ev.v.Name + " " + f, Vantage: ev.v.Name, Severity: check.Low,
					Title:    "La sortie en liste blanche est refusée par l'origine en " + f,
					Evidence: "aucun de ses " + strconv.Itoa(len(hs)) + " hôtes autorisés n'est servi en direct : " + p})
			}
		}
		if len(parts) == 0 || len(hs) == 0 {
			continue
		}
		if allowed {
			out = append(out, check.Finding{Check: "origin.allowed", Target: ev.v.Name, Vantage: ev.v.Name, Severity: check.Info,
				Title:    "Origine jointe en direct depuis la sortie en liste blanche " + ev.v.Name,
				Evidence: strings.Join(parts, " ; ") + " — hôtes autorisés pour cette sortie, en HTTPS (443) et HTTP (80)"})
			continue
		}
		title := "Origine fermée aux inconnus depuis " + ev.v.Name
		if len(tested) == 0 {
			title = "Origine non testée depuis " + ev.v.Name
		} else if fam["IPv4"].served+fam["IPv6"].served > 0 {
			title = "Origine servie en direct à un inconnu depuis " + ev.v.Name + " (détail : origin.bypass)"
		}
		out = append(out, check.Finding{Check: "origin.closed", Target: ev.v.Name, Vantage: ev.v.Name, Severity: check.Info,
			Title:    title,
			Evidence: strings.Join(parts, " ; ") + " — connexion directe à l'IP d'origine, en HTTPS (443) et HTTP (80), avec le nom de chaque hôte"})
	}
	return out
}

func family(a netip.Addr) string {
	if a.Unmap().Is4() {
		return "IPv4"
	}
	return "IPv6"
}

var originPort, originHTTPPort = 443, 80 // variables pour les tests

type endpoint struct {
	addr   netip.Addr
	scheme string
	port   int
}

// originEndpoints : chaque adresse d'origine en HTTPS puis en HTTP.
func originEndpoints(origins []netip.Addr) []endpoint {
	var out []endpoint
	for _, o := range origins {
		out = append(out, endpoint{o, "https", originPort}, endpoint{o, "http", originHTTPPort})
	}
	return out
}

var errDial = errors.New("connexion TCP impossible")

func direct(ctx context.Context, g *scan.Guard, v scan.Vantage, origin netip.Addr, host, scheme string, port int) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			c, err := g.Dial(ctx, v, origin.String(), port)
			if err != nil {
				return nil, fmt.Errorf("%w : %w", errDial, err)
			}
			return c, nil
		},
		// On teste l'accès, pas le certificat (déjà jugé par tlsscan).
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+host+"/", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 16<<10))
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), nil
}
