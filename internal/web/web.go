// Package web sert l'interface : vue d'ensemble, écarts, problèmes, hôtes,
// passages, inventaire et réglages.
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmhtml "github.com/yuin/goldmark/renderer/html"
	"github.com/yuin/goldmark/text"
	"github.com/yuin/goldmark/util"

	"github.com/neotoxicfr/vigie/internal/ai"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/engine"
	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/source/manual"
	"github.com/neotoxicfr/vigie/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Runner lance les passages ; un seul à la fois.
type Runner interface {
	Start() (int64, error)
	StartHost(host string) (int64, error)
	Current() (int64, bool)
	Progress() engine.Progress
}

type Deps struct {
	MCP      http.Handler // monté sur /mcp ; il gère lui-même son jeton
	Cfg      *config.Config
	Settings *settings.Live
	Store    *store.Store
	Manual   *manual.Manual
	Sources  func(config.Runtime) []source.Source
	Runner   Runner
	Version  string
}

type Server struct {
	Deps
	auth  *auth
	pages map[string]*template.Template

	amu       sync.Mutex
	analyzing map[int64]string // passage → "" en cours, sinon message d'échec
	awg       sync.WaitGroup   // analyses en cours, attendues à l'arrêt
}

// Wait attend les analyses IA en cours, au plus timeout.
func (s *Server) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { s.awg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// Cadences proposées pour les passages planifiés ; "0" = désactivé.
var Cadences = []struct{ Value, Label string }{
	{"0", "désactivé"}, {"6h", "toutes les 6 h"}, {"24h", "chaque jour"}, {"168h", "chaque semaine"}, {"720h", "tous les 30 jours"},
}

var moisFR = [...]string{"janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."}

// when : « 23 oct. 09:56 », l'année seulement si ce n'est pas l'année en cours.
func when(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	t = t.Local()
	if t.Year() != time.Now().Year() {
		return fmt.Sprintf("%d %s %d %02d:%02d", t.Day(), moisFR[t.Month()-1], t.Year(), t.Hour(), t.Minute())
	}
	return fmt.Sprintf("%d %s %02d:%02d", t.Day(), moisFR[t.Month()-1], t.Hour(), t.Minute())
}

func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case t.IsZero():
		return ""
	case d < time.Minute:
		return "à l'instant"
	case d < time.Hour:
		return fmt.Sprintf("il y a %d min", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("il y a %d h", int(d.Hours()))
	}
	return fmt.Sprintf("il y a %d j", int(d.Hours()/24))
}

func New(d Deps) (*Server, error) {
	key, err := loadKey(filepath.Join(d.Cfg.DataDir, "session.key"))
	if err != nil {
		return nil, err
	}
	s := &Server{Deps: d, auth: &auth{cfg: d.Cfg.Auth, key: key, st: d.Store, fails: map[string]*failState{}},
		pages: map[string]*template.Template{}, analyzing: map[int64]string{}}
	funcs := template.FuncMap{
		"when": when,
		"ref":  runRef,
		"ago":  ago,
		"since": func(a, b time.Time) string {
			if a.IsZero() || b.IsZero() {
				return "—"
			}
			return b.Sub(a).Round(time.Second).String()
		},
		"sevclass": func(s check.Severity) string { return "sev-" + strconv.Itoa(int(s)) },
		"markdown": markdown,
		"spark":    sparkline,
		"vlabel":   vantageLabel,
		"vclass": func(v string) string {
			if _, known := vantageLabels[v]; known {
				return "v-" + v
			}
			return "v-exit" // sortie par proxy, nommée par l'utilisateur
		},
		"pct": func(a, b int) int {
			if b == 0 {
				return 0
			}
			return a * 100 / b
		},
		"join": strings.Join,
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
	}
	base := template.Must(template.New("").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/parts.html"))
	names, _ := fs.Glob(assets, "templates/*.html")
	for _, n := range names {
		if n == "templates/layout.html" || n == "templates/parts.html" {
			continue
		}
		t := template.Must(template.Must(base.Clone()).ParseFS(assets, n))
		s.pages[strings.TrimSuffix(filepath.Base(n), ".html")] = t
	}
	return s, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /api/summary", s.summary) // jeton porteur propre, hors session et CSRF
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("POST /logout", s.authed(s.logout))

	mux.HandleFunc("GET /{$}", s.authed(s.overview))
	mux.HandleFunc("GET /issues", s.authed(s.issuesPage))
	mux.HandleFunc("GET /issue/{key}", s.authed(s.issuePage))
	mux.HandleFunc("GET /problems", s.authed(s.problemsPage))
	mux.HandleFunc("GET /hosts", s.authed(s.hostsPage))
	mux.HandleFunc("GET /host/{host}", s.authed(s.hostPage))
	mux.HandleFunc("GET /runs", s.authed(s.runsPage))
	mux.HandleFunc("GET /runs/{ref}/export.json", s.authed(s.export))
	mux.HandleFunc("GET /inventory", s.authed(s.inventory))
	mux.HandleFunc("POST /sources/test", s.authed(s.inventory))
	mux.HandleFunc("GET /settings", s.authed(s.settingsPage))
	mux.HandleFunc("GET /api/progress", s.authed(s.progress))

	mux.HandleFunc("POST /run", s.authed(s.startRun))
	mux.HandleFunc("POST /retest", s.authed(s.retest))
	mux.HandleFunc("POST /accept", s.authed(s.accept))
	mux.HandleFunc("POST /unaccept", s.authed(s.unaccept))
	mux.HandleFunc("POST /targets", s.authed(s.addTarget))
	mux.HandleFunc("POST /targets/{id}/delete", s.authed(s.deleteTarget))
	mux.HandleFunc("POST /settings/{section}", s.authed(s.saveSettings))
	mux.HandleFunc("POST /runs/{ref}/analyze", s.authed(s.analyze))
	if s.MCP != nil {
		mux.Handle("/mcp", s.MCP) // jeton porteur propre, hors session et CSRF
	}
	return headers(mux)
}

// headers : la page de vigie applique ce qu'elle audite.
func headers(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		hd.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		hd.Set("Cross-Origin-Opener-Policy", "same-origin")
		hd.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.ServeHTTP(w, r)
	})
}

type userKey struct{}

func (s *Server) authed(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.auth.user(r)
		if u == "" {
			if len(s.Cfg.Auth.Users) > 0 && r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "authentification requise", http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			if !s.auth.checkCSRF(r, u) {
				http.Error(w, "requête refusée (jeton CSRF ou origine)", http.StatusForbidden)
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}
}

func user(r *http.Request) string { u, _ := r.Context().Value(userKey{}).(string); return u }

type page struct {
	Title, User, CSRF, Version string
	Nav                        string
	Flash, Error               string
	Last                       *store.Run
	Progress                   engine.Progress
	Path                       string
	Data                       any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title, nav string, data any) {
	p := page{Title: title, User: user(r), Version: s.Version, Nav: nav, Data: data, Path: r.URL.RequestURI()}
	// Seuls les messages signés par vigie s'affichent : un lien forgé ne peut pas
	// faire dire n'importe quoi à la page.
	q := r.URL.Query()
	if msg := q.Get("ok"); msg != "" && hmac.Equal([]byte(q.Get("sig")), []byte(s.auth.sign("flash|ok|"+msg))) {
		p.Flash = msg
	}
	if msg := q.Get("err"); msg != "" && hmac.Equal([]byte(q.Get("sig")), []byte(s.auth.sign("flash|err|"+msg))) {
		p.Error = msg
	}
	p.CSRF = s.auth.csrfToken(r.Context(), p.User)
	if p.User != "" {
		if run, err := s.lastRun(r.Context()); err == nil {
			p.Last = run
		}
		p.Progress = s.Runner.Progress()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl := "layout"
	if q.Get("panel") == "1" {
		tpl = "panel" // fragment chargé dans le panneau latéral
	}
	if err := s.pages[name].ExecuteTemplate(w, tpl, p); err != nil {
		log.Printf("gabarit %s : %v", name, err)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	log.Printf("web : %v", err)
	http.Error(w, "erreur interne, voir le journal", http.StatusInternalServerError)
}

func (s *Server) back(w http.ResponseWriter, r *http.Request, to, key, msg string) {
	to, frag, _ := strings.Cut(to, "#") // le message va dans la requête, l'ancre reste à la fin
	sep := "?"
	if strings.Contains(to, "?") {
		sep = "&"
	}
	u := to + sep + key + "=" + url.QueryEscape(msg) + "&sig=" + s.auth.sign("flash|"+key+"|"+msg)
	if frag != "" {
		u += "#" + frag
	}
	http.Redirect(w, r, u, http.StatusSeeOther)
}

// safeBack n'accepte qu'un retour local (« /… » sans « // »), contre les redirections ouvertes.
func safeBack(v string) string {
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, "\\") {
		return "/"
	}
	for _, c := range v { // une tabulation ou un saut de ligne transforme « /\t/x » en « //x » pour le navigateur
		if c < 0x20 || c == 0x7f {
			return "/"
		}
	}
	if u, err := url.Parse(v); err != nil || u.Host != "" || u.Scheme != "" {
		return "/"
	}
	return v
}

func (s *Server) progress(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(s.Runner.Progress())
}

// --- connexion ---

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if len(s.Cfg.Auth.Users) == 0 {
		http.Error(w, "connexion par le proxy d'authentification", http.StatusNotFound)
		return
	}
	s.render(w, r, "login", "Connexion", "", nil)
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if len(s.Cfg.Auth.Users) == 0 {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if !s.auth.checkCSRF(r, "") {
		http.Error(w, "requête refusée (jeton CSRF ou origine)", http.StatusForbidden)
		return
	}
	ok, locked := s.auth.login(s.auth.clientIP(r), r.PostFormValue("user"), r.PostFormValue("password"))
	switch {
	case locked:
		s.back(w, r, "/login", "err", "Trop d'échecs : réessaie dans 15 minutes.")
	case !ok:
		s.back(w, r, "/login", "err", "Identifiant ou mot de passe incorrect.")
	default:
		s.auth.setSession(w, r, r.PostFormValue("user"))
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if len(s.Cfg.Auth.Users) > 0 {
		if err := s.auth.revoke(r.Context(), user(r)); err != nil {
			s.fail(w, err)
			return
		}
	}
	s.auth.clearSession(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- petits rendus ---

// sparkline dessine une courbe SVG en ligne ; seuls des nombres entrent dans le
// balisage, donc rien d'injectable.
func sparkline(vals []int, w, h int) template.HTML {
	if len(vals) < 2 {
		return ""
	}
	max, flat := 1, true
	for _, v := range vals {
		if v > max {
			max = v
		}
		flat = flat && v == vals[0]
	}
	if flat { // rien n'a bougé : une ligne au milieu, pas un aplat trompeur
		return template.HTML(fmt.Sprintf(`<svg class="spark" viewBox="0 0 %d %d" width="%d" height="%d" aria-hidden="true">`+
			`<line x1="1" y1="%d" x2="%d" y2="%d" class="spark-line"/></svg>`, w, h, w, h, h/2, w-1, h/2))
	}
	var pts []string
	for i, v := range vals {
		x := float64(i)*float64(w-2)/float64(len(vals)-1) + 1
		y := float64(h-2) - float64(v)*float64(h-4)/float64(max) + 1
		pts = append(pts, fmt.Sprintf("%.1f,%.1f", x, math.Round(y*10)/10))
	}
	area := "1," + strconv.Itoa(h-1) + " " + strings.Join(pts, " ") + " " + strconv.Itoa(w-1) + "," + strconv.Itoa(h-1)
	return template.HTML(fmt.Sprintf(`<svg class="spark" viewBox="0 0 %d %d" width="%d" height="%d" aria-hidden="true">`+
		`<polygon points="%s" class="spark-area"/><polyline points="%s" class="spark-line"/></svg>`, w, h, w, h, area, strings.Join(pts, " ")))
}

var vantageLabels = map[string]string{"public": "public", "dns": "DNS", "origine": "origine", "interne": "interne", "inconnu": "inconnu", "config": "config"}

func vantageLabel(v string) string {
	if l, ok := vantageLabels[v]; ok {
		return l
	}
	return v
}

// md rend la réponse du modèle : Markdown GFM (tableaux, listes numérotées,
// liens). Le HTML brut est omis et les URL dangereuses neutralisées (défauts
// de goldmark, sans WithUnsafe) : la réponse d'un modèle n'injecte jamais de HTML.
var md = goldmark.New(
	goldmark.WithExtensions(extension.Strikethrough,
		// Alignement en attribut : la CSP interdit les styles en ligne.
		extension.NewTable(extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute))),
	goldmark.WithParserOptions(parser.WithASTTransformers(util.Prioritized(headingShift{}, 100))),
	// Le modèle passe souvent à la ligne sans ligne vide après un titre en gras.
	goldmark.WithRendererOptions(gmhtml.WithHardWraps()),
)

// headingShift descend les titres de deux niveaux : la page porte déjà h1 et h2.
type headingShift struct{}

func (headingShift) Transform(doc *ast.Document, _ text.Reader, _ parser.Context) {
	ast.Walk(doc, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if h, ok := n.(*ast.Heading); ok && entering {
			h.Level = min(h.Level+2, 6)
		}
		return ast.WalkContinue, nil
	})
}

func markdown(src string) template.HTML {
	var b bytes.Buffer
	if err := md.Convert([]byte(src), &b); err != nil {
		return template.HTML("<pre>" + template.HTMLEscapeString(src) + "</pre>")
	}
	return template.HTML(b.String())
}

// aiProvider construit le fournisseur depuis les réglages du moment ; nil, avec
// la raison, si aucun n'est configuré ou si sa clé manque.
func (s *Server) aiProvider() (ai.Provider, string) {
	r := s.Settings.Get()
	if r.AI.Provider == "" {
		return nil, ""
	}
	p, err := ai.New(r.AI)
	if err != nil {
		return nil, err.Error()
	}
	return p, ""
}
