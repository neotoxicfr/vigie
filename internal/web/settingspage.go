package web

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/cdnprov/cloudflare"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

// --- inventaire ---

type sourceStatus struct {
	Name   string
	Routes int
	Err    string
}

type invData struct {
	Routes  []source.Route
	Targets []store.Target
	Tested  []sourceStatus
	Sources []string
}

func (s *Server) inventory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := invData{Routes: s.inventoryRoutes(ctx)}
	srcs := s.Sources(s.Settings.Get())
	for _, src := range srcs {
		d.Sources = append(d.Sources, src.Name())
	}
	if r.Method == http.MethodPost { // test des sources à la demande
		tctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		for _, src := range srcs {
			rs, err := src.Discover(tctx)
			st := sourceStatus{Name: src.Name(), Routes: len(rs)}
			if err != nil {
				st.Err = err.Error()
			}
			d.Tested = append(d.Tested, st)
		}
	}
	var err error
	if d.Targets, err = s.Store.Targets(ctx); err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "inventory", "Inventaire", "inventory", d)
}

// --- réglages ---

type secret struct {
	Path  string
	State string // absent, vide, présent, trop court
	OK    bool
}

func secretState(path string, min int) secret {
	s := secret{Path: path}
	if path == "" {
		s.State = "non configuré"
		return s
	}
	if _, err := os.Stat(path); err != nil {
		s.State = "fichier absent"
		return s
	}
	v := settings.Secret(path)
	switch {
	case v == "":
		s.State = "vide"
	case len(v) < min:
		s.State = fmt.Sprintf("trop court (%d caractères au moins)", min)
	default:
		s.State, s.OK = "présent", true
	}
	return s
}

func cfState(path string) secret {
	s := secretState(path, 20)
	if s.OK && cloudflare.IsGlobalKey(settings.Secret(path)) {
		s.State, s.OK = "Global API Key détectée, il faut un jeton API restreint", false
	}
	return s
}

type exclusion struct {
	Check string
	Acc   *store.Acceptance
}

type settingsData struct {
	R          config.Runtime
	Cadence    string
	Cadences   any
	CF, AI     secret
	MCP, API   secret
	MCPURL     string
	APIURL     string
	Exclusions []exclusion
	Text       map[string]string // listes prêtes pour les zones de texte
}

func addrsText(as []netip.Addr) string {
	var s []string
	for _, a := range as {
		s = append(s, a.String())
	}
	return strings.Join(s, "\n")
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt := s.Settings.Get()
	d := settingsData{R: rt, Cadences: Cadences,
		CF:  cfState(rt.CDN.Cloudflare.TokenFile),
		AI:  secretState(rt.AI.APIKeyFile, 1),
		MCP: secretState(rt.MCP.TokenFile, 32),
		API: secretState(rt.API.TokenFile, 32),
	}
	d.Cadence, _ = s.Store.Setting(ctx, "cadence", "0")
	scheme := "https"
	if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") == "" {
		scheme = "http"
	}
	d.MCPURL = scheme + "://" + r.Host + "/mcp"
	d.APIURL = scheme + "://" + r.Host + "/api/summary"
	ex := append([]string{}, rt.Exclusions...)
	sort.Strings(ex)
	for _, c := range ex {
		a, _ := s.Store.GetAcceptance(ctx, "check:"+c)
		d.Exclusions = append(d.Exclusions, exclusion{c, a})
	}
	var ports []string
	for _, p := range rt.Scan.Ports {
		ports = append(ports, strconv.Itoa(p))
	}
	d.Text = map[string]string{
		"public_ips": addrsText(rt.PublicIPs),
		"internal":   addrsText(rt.Vantages.Internal),
		"public":     strings.Join(rt.Policy.Public, "\n"),
		"ports":      strings.Join(ports, ", "),
		"pages":      pagesText(rt.Scan.Pages),
	}
	s.render(w, r, "settings", "Réglages", "settings", d)
}

func lines(v string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(v, func(c rune) bool { return c == '\n' || c == ',' || c == ' ' || c == '\r' || c == '\t' }) {
		out = append(out, f)
	}
	return out
}

func parseAddrs(v, field string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, f := range lines(v) {
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("%s : adresse invalide %q", field, f)
		}
		out = append(out, a)
	}
	return out, nil
}

// saveSettings applique une section du formulaire aux réglages courants ; la
// validation complète passe avant tout enregistrement.
func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request) {
	rt := s.Settings.Get()
	f := r.PostForm
	sec := r.PathValue("section")
	to := "/settings#" + sec
	var err error
	switch sec {
	case "sources":
		oldPass := map[string]string{}
		for _, t := range rt.Sources.Traefik {
			oldPass[t.Name] = t.PasswordFile
		}
		rt.Sources = config.Sources{}
		for i := range f["traefik_name"] {
			n, u := strings.TrimSpace(f["traefik_name"][i]), strings.TrimSpace(at(f["traefik_url"], i))
			if n == "" && u == "" {
				continue
			}
			pass, e := secretPath(at(f["traefik_pass"], i), oldPass[n], "Traefik "+n)
			if e != nil {
				err = e
				break
			}
			rt.Sources.Traefik = append(rt.Sources.Traefik, config.Traefik{Name: n, URL: u,
				Username: strings.TrimSpace(at(f["traefik_user"], i)), PasswordFile: pass})
		}
		for kind, dst := range map[string]*[]config.Named{"caddy": &rt.Sources.Caddy, "nginx": &rt.Sources.Nginx, "npm": &rt.Sources.NPM} {
			for i := range f[kind+"_name"] {
				n, l := strings.TrimSpace(f[kind+"_name"][i]), strings.TrimSpace(at(f[kind+"_loc"], i))
				if n == "" && l == "" {
					continue
				}
				*dst = append(*dst, config.Named{Name: n, Location: l})
			}
		}
	case "vantages":
		if rt.PublicIPs, err = parseAddrs(f.Get("public_ips"), "IP publiques"); err == nil {
			rt.Vantages.Internal, err = parseAddrs(f.Get("internal"), "interne")
		}
		rt.Scan.Resolver = strings.TrimSpace(f.Get("resolver"))
		oldPass := map[string]string{}
		for _, p := range rt.Vantages.Proxies {
			oldPass[p.Name] = p.PasswordFile
		}
		rt.Vantages.Proxies = nil
		for i := range f["exit_name"] {
			n, u := strings.TrimSpace(f["exit_name"][i]), strings.TrimSpace(at(f["exit_url"], i))
			if n == "" && u == "" {
				continue
			}
			pass, e := secretPath(at(f["exit_pass"], i), oldPass[n], "sortie "+n)
			if e != nil {
				err = e
				break
			}
			rt.Vantages.Proxies = append(rt.Vantages.Proxies, config.ExitProxy{Name: n, URL: u,
				Username: strings.TrimSpace(at(f["exit_user"], i)), PasswordFile: pass})
		}
	case "policy":
		rt.Policy.Public = lines(f.Get("public"))
		rt.Policy.AutheliaConfig = strings.TrimSpace(f.Get("authelia"))
	case "scan":
		if rt.Scan.Budget, err = strconv.Atoi(strings.TrimSpace(f.Get("budget"))); err != nil {
			err = fmt.Errorf("budget : nombre attendu")
			break
		}
		rt.Scan.Timeout = strings.TrimSpace(f.Get("timeout"))
		if rt.Scan.Pages, err = parsePages(f.Get("pages")); err != nil {
			break
		}
		rt.Scan.Ports = nil
		for _, p := range lines(f.Get("ports")) {
			n, e := strconv.Atoi(p)
			if e != nil {
				err = fmt.Errorf("ports : %q n'est pas un nombre", p)
				break
			}
			rt.Scan.Ports = append(rt.Scan.Ports, n)
		}
		if err == nil {
			c := f.Get("cadence")
			valid := false
			for _, x := range Cadences {
				valid = valid || x.Value == c
			}
			if !valid {
				err = fmt.Errorf("cadence inconnue")
			} else if e := s.Store.SetSetting(r.Context(), "cadence", c); e != nil {
				s.fail(w, e)
				return
			}
		}
	case "cloudflare":
		rt.CDN.Cloudflare.Enabled = f.Get("enabled") == "1"
		rt.CDN.Cloudflare.TokenFile, err = secretPath(f.Get("token_file"), rt.CDN.Cloudflare.TokenFile, "jeton Cloudflare")
	case "cloudflare-test":
		s.testCloudflare(w, r, rt)
		return
	case "ai":
		rt.AI.Provider = f.Get("provider")
		rt.AI.Model = strings.TrimSpace(f.Get("model"))
		rt.AI.BaseURL = strings.TrimSpace(f.Get("base_url"))
		rt.AI.Context = strings.TrimSpace(strings.ReplaceAll(f.Get("context"), "\r\n", "\n"))
		rt.AI.APIKeyFile, err = secretPath(f.Get("key_file"), rt.AI.APIKeyFile, "clé IA")
	case "mcp":
		if rt.MCP.TokenFile, err = secretPath(f.Get("token_file"), rt.MCP.TokenFile, "jeton MCP"); err == nil {
			rt.API.TokenFile, err = secretPath(f.Get("api_token_file"), rt.API.TokenFile, "jeton du résumé")
		}
	default:
		http.NotFound(w, r)
		return
	}
	if err == nil {
		err = s.Settings.Set(r.Context(), rt)
	}
	if err != nil {
		s.back(w, r, to, "err", err.Error())
		return
	}
	s.back(w, r, to, "ok", "Réglages enregistrés : ils valent dès le prochain passage.")
}

// secretDir : seul dossier où l'interface peut désigner un secret. Sinon, choisir
// « /data/session.key » comme fichier de clé et une URL à soi enverrait ce
// fichier ailleurs ; le fichier de configuration, lui, reste libre.
var secretDir = "/run/secrets/" // variable pour les tests

// secretPath accepte un chemin vide, inchangé, ou un fichier direct de /run/secrets.
func secretPath(newPath, old, field string) (string, error) {
	newPath = strings.TrimSpace(newPath)
	if newPath == "" || newPath == old {
		return newPath, nil
	}
	if path.Clean(newPath) != newPath || !strings.HasPrefix(newPath, secretDir) || strings.Contains(newPath[len(secretDir):], "/") {
		return "", fmt.Errorf("%s : depuis l'interface, un secret doit être un fichier de %s (Docker secrets)", field, secretDir)
	}
	return newPath, nil
}

func at(v []string, i int) string {
	if i < len(v) {
		return v[i]
	}
	return ""
}

// testCloudflare lit la zone des hôtes connus et rend un bilan court.
func (s *Server) testCloudflare(w http.ResponseWriter, r *http.Request, rt config.Runtime) {
	var hosts []string
	seen := map[string]bool{}
	for _, rr := range s.inventoryRoutes(r.Context()) {
		for _, h := range rr.Hosts {
			if !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	if len(hosts) == 0 {
		s.back(w, r, "/settings#cloudflare", "err", "Aucun hôte connu : lance d'abord un passage.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	res, err := cloudflare.New(rt.CDN.Cloudflare.TokenFile, "").Scan(ctx, hosts)
	if err != nil {
		s.back(w, r, "/settings#cloudflare", "err", "Cloudflare : "+err.Error())
		return
	}
	var scope []string
	for _, f := range res.Findings {
		if f.Check == "cf.token.scope" || f.Check == "cf.zone.missing" {
			scope = append(scope, f.Title)
		}
	}
	msg := fmt.Sprintf("Cloudflare répond : %d constat(s), %d hôte(s) avec règles lues.", len(res.Findings), len(res.Notes))
	if len(scope) > 0 {
		msg += " À voir : " + strings.Join(scope, " ; ")
	}
	s.back(w, r, "/settings#cloudflare", "ok", msg)
}

// pages : une ligne « hôte /chemin » par hôte dont la racine n'est pas la page à juger.
func pagesText(m map[string]string) string {
	var ls []string
	for h, p := range m {
		ls = append(ls, h+" "+p)
	}
	sort.Strings(ls)
	return strings.Join(ls, "\n")
}

func parsePages(v string) (map[string]string, error) {
	out := map[string]string{}
	for _, l := range strings.Split(v, "\n") {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			return nil, fmt.Errorf("pages : « %s » : attendu « hôte /chemin »", strings.TrimSpace(l))
		}
		out[strings.ToLower(f[0])] = f[1]
	}
	return out, nil
}
