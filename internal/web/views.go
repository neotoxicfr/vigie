package web

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/kb"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

// row : un écart prêt à afficher.
type row struct {
	store.Issue
	Host     string // check.Unit de la cible
	Excluded bool   // contrôle assumé partout (exclu des passages)
}

// lastRun : le dernier passage terminé, complet ou re-test.
func (s *Server) lastRun(ctx context.Context) (*store.Run, error) {
	runs, err := s.Store.Runs(ctx, 50)
	if err != nil {
		return nil, err
	}
	for i := range runs {
		if runs[i].Status == "ok" || runs[i].Status == "partial" {
			return &runs[i], nil
		}
	}
	return nil, sql.ErrNoRows
}

// state rend les écarts d'un passage (0 = le dernier), exclusions appliquées.
func (s *Server) state(ctx context.Context, runID int64) (*store.Run, []row, error) {
	var run *store.Run
	if runID > 0 {
		r, err := s.Store.GetRun(ctx, runID)
		if err != nil {
			return nil, nil, err
		}
		run = &r
	} else {
		r, err := s.lastRun(ctx)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		run = r
	}
	ds, err := s.Store.Compare(ctx, run.ID)
	if err != nil {
		return nil, nil, err
	}
	ex := map[string]bool{}
	for _, c := range s.Settings.Get().Exclusions {
		ex[c] = true
	}
	var rows []row
	for _, is := range store.Group(ds) {
		r := row{Issue: is, Host: check.Unit(is.Target), Excluded: ex[is.Check]}
		if r.Excluded && r.Accepted == nil {
			a, _ := s.Store.GetAcceptance(ctx, "check:"+is.Check)
			if a == nil {
				a = &store.Acceptance{Note: "assumé partout"}
			}
			r.Accepted = a
		}
		rows = append(rows, r)
	}
	return run, rows, nil
}

// --- filtres ---

type filter struct {
	Tab  string
	Sev  [4]bool
	Vue  map[string]bool
	Q    string
	Host string
	Ref  string // passage consulté, désigné par sa date (runRef)
	Run  int64  // son identifiant interne, résolu par le serveur
}

func parseFilter(q url.Values) filter {
	f := filter{Tab: q.Get("etat"), Q: strings.TrimSpace(q.Get("q")), Host: strings.ToLower(q.Get("host")), Vue: map[string]bool{}}
	f.Ref = q.Get("passage")
	any := false
	for _, v := range q["sev"] {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= 3 {
			f.Sev[n], any = true, true
		}
	}
	if !any { // défaut : les écarts, sans l'info
		f.Sev = [4]bool{false, true, true, true}
	}
	for _, v := range q["vue"] {
		f.Vue[v] = true
	}
	return f
}

// query reconstruit l'URL du filtre, onglet remplacé.
func (f filter) query(base, tab string) string {
	v := url.Values{}
	if tab != "" {
		v.Set("etat", tab)
	}
	for i, on := range f.Sev {
		if on {
			v.Add("sev", strconv.Itoa(i))
		}
	}
	for k := range f.Vue {
		v.Add("vue", k)
	}
	if f.Q != "" {
		v.Set("q", f.Q)
	}
	if f.Ref != "" {
		v.Set("passage", f.Ref)
	}
	if len(v) == 0 {
		return base
	}
	return base + "?" + v.Encode()
}

func inTab(r row, tab string) bool {
	accepted := r.Accepted != nil && r.State != store.Resolved
	switch tab {
	case "":
		return r.State != store.Resolved && !accepted
	case "nouveau", "inchangé":
		return string(r.State) == tab && !accepted
	case "résolu":
		return r.State == store.Resolved
	case "assumé":
		return accepted
	}
	return true
}

func (f filter) keep(r row) bool {
	if !f.Sev[r.Severity] {
		return false
	}
	if f.Host != "" && r.Host != f.Host {
		return false
	}
	if len(f.Vue) > 0 {
		hit := false
		for _, v := range r.Vantages {
			hit = hit || f.Vue[v.Name]
		}
		if !hit {
			return false
		}
	}
	return f.Q == "" || strings.Contains(strings.ToLower(r.Target+" "+r.Check+" "+r.Title), strings.ToLower(f.Q))
}

var tabs = []struct{ Key, Label string }{
	{"", "Ouverts"}, {"nouveau", "Nouveaux"}, {"inchangé", "Toujours là"}, {"résolu", "Résolus"}, {"assumé", "Assumés"}, {"tout", "Tout"},
}

type tabLink struct {
	Label, URL string
	Count      int
	Current    bool
}

func (f filter) tabs(base string, rows []row) []tabLink {
	var out []tabLink
	for _, t := range tabs {
		n := 0
		for _, r := range rows {
			if f.keep(r) && inTab(r, t.Key) {
				n++
			}
		}
		out = append(out, tabLink{Label: t.Label, URL: f.query(base, t.Key), Count: n, Current: f.Tab == t.Key})
	}
	return out
}

// --- notes ---

// grade note un hôte d'après ses écarts ouverts : un élevé fait tomber à C au mieux.
func grade(open [4]int) (string, int) {
	score := 100 - 30*open[3] - 10*open[2] - 3*open[1]
	if score < 0 {
		score = 0
	}
	switch {
	case score >= 90:
		return "A", score
	case score >= 75:
		return "B", score
	case score >= 60:
		return "C", score
	case score >= 40:
		return "D", score
	case score >= 20:
		return "E", score
	}
	return "F", score
}

type hostRow struct {
	Host         string
	Grade        string
	Score        int
	Open         [4]int
	OpenTotal    int
	New          int
	Trend        []int
	Vantages     []string
	Carried      bool
	Route, Chain string
}

// hostRows agrège les écarts ouverts par hôte, avec leur tendance.
func (s *Server) hostRows(ctx context.Context, rows []row) []hostRow {
	by := map[string]*hostRow{}
	for _, r := range rows {
		h := by[r.Host]
		if h == nil {
			h = &hostRow{Host: r.Host}
			by[r.Host] = h
		}
		if inTab(r, "") {
			h.Open[r.Severity]++
			if r.Severity > 0 {
				h.OpenTotal++
			}
			if r.State == store.New {
				h.New++
			}
		}
		h.Carried = h.Carried || r.Carried
	}
	counts, _ := s.Store.IssueCounts(ctx, 20)
	var runIDs []int64
	per := map[string]map[int64]int{}
	seen := map[int64]bool{}
	for _, c := range counts {
		if !seen[c.Run] {
			seen[c.Run] = true
			runIDs = append(runIDs, c.Run)
		}
		if per[c.Unit] == nil {
			per[c.Unit] = map[int64]int{}
		}
		per[c.Unit][c.Run] += c.Count
	}
	var out []hostRow
	for _, h := range by {
		h.Grade, h.Score = grade(h.Open)
		for _, id := range runIDs {
			h.Trend = append(h.Trend, per[h.Host][id])
		}
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score < out[j].Score
		}
		return out[i].Host < out[j].Host
	})
	return out
}

// --- vue d'ensemble ---

type overviewData struct {
	Run       *store.Run
	Open      [4]int
	OpenTotal int
	New       int
	Hosts     int
	Grades    []gradeCount
	Trend     []int
	TrendFrom string
	Fresh     []row
	Worst     []hostRow
	Runs      []store.Run
	Cadence   string
	Cadences  any
	// Analyse IA du dernier passage : section affichée seulement si une clé est en place.
	AI        string // nom du fournisseur, vide = pas d'IA utilisable
	Analysis  *store.Analysis
	Analyzing bool
	AIError   string
}

type gradeCount struct {
	Grade string
	N     int
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	run, rows, err := s.state(ctx, 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := overviewData{Run: run, Cadences: Cadences}
	d.Cadence, _ = s.Store.Setting(ctx, "cadence", "0")
	if p, _ := s.aiProvider(); p != nil && run != nil {
		d.AI = p.Name()
		d.Analysis, d.Analyzing, d.AIError = s.analysisState(ctx, run.ID)
	}
	for _, x := range rows {
		if inTab(x, "") && x.Severity > 0 {
			d.Open[x.Severity]++
			d.OpenTotal++
			if x.State == store.New {
				d.New++
				if len(d.Fresh) < 8 {
					d.Fresh = append(d.Fresh, x)
				}
			}
		}
	}
	sort.SliceStable(d.Fresh, func(i, j int) bool { return d.Fresh[i].Severity > d.Fresh[j].Severity })
	hosts := s.hostRows(ctx, rows)
	d.Hosts = len(hosts)
	gc := map[string]int{}
	for _, h := range hosts {
		gc[h.Grade]++
	}
	for _, g := range []string{"A", "B", "C", "D", "E", "F"} {
		d.Grades = append(d.Grades, gradeCount{g, gc[g]})
	}
	if len(hosts) > 6 {
		hosts = hosts[:6]
	}
	d.Worst = hosts
	runs, _ := s.Store.Runs(ctx, 40)
	for i := len(runs) - 1; i >= 0; i-- {
		if runs[i].Scope == "" && (runs[i].Status == "ok" || runs[i].Status == "partial") {
			if d.TrendFrom == "" {
				d.TrendFrom = when(runs[i].Started)
			}
			d.Trend = append(d.Trend, runs[i].Issues)
		}
	}
	if len(runs) > 5 {
		runs = runs[:5]
	}
	d.Runs = runs
	s.render(w, r, "overview", "Vue d'ensemble", "overview", d)
}

// --- écarts ---

type issuesData struct {
	Run        *store.Run
	Rows       []row
	Tabs       []tabLink
	F          filter
	Vantages   []string
	Total      int
	Base       string
	HostFilter string
}

func (s *Server) issuesData(r *http.Request, base string) (issuesData, error) {
	f := parseFilter(r.URL.Query())
	f.Run = s.runID(r.Context(), f.Ref)
	run, rows, err := s.state(r.Context(), f.Run)
	if err != nil {
		return issuesData{}, err
	}
	d := issuesData{Run: run, F: f, Base: base, Tabs: f.tabs(base, rows), HostFilter: f.Host}
	vs := map[string]bool{}
	for _, x := range rows {
		for _, v := range x.Vantages {
			vs[v.Name] = true
		}
		if f.keep(x) && inTab(x, f.Tab) {
			d.Rows = append(d.Rows, x)
		}
	}
	d.Total = len(d.Rows)
	for v := range vs {
		d.Vantages = append(d.Vantages, v)
	}
	sort.Slice(d.Vantages, func(i, j int) bool { return vantageOrder(d.Vantages[i]) < vantageOrder(d.Vantages[j]) })
	sort.SliceStable(d.Rows, func(i, j int) bool {
		a, b := d.Rows[i], d.Rows[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if (a.State == store.New) != (b.State == store.New) {
			return a.State == store.New
		}
		if a.Host != b.Host {
			return a.Host < b.Host
		}
		return a.Check < b.Check
	})
	return d, nil
}

func vantageOrder(v string) int {
	for i, x := range []string{"public", "dns", "origine", "interne", "inconnu", "config"} {
		if v == x {
			return i
		}
	}
	return 9
}

func (s *Server) issuesPage(w http.ResponseWriter, r *http.Request) {
	d, err := s.issuesData(r, "/issues")
	if err != nil {
		s.fail(w, err)
		return
	}
	title := "Écarts"
	if d.F.Run > 0 && d.Run != nil {
		title = "Écarts du passage du " + when(d.Run.Started)
	}
	s.render(w, r, "issues", title, "issues", d)
}

// --- un écart ---

type fixView struct {
	Tab, Label, Code, Proxy string
}

type issueData struct {
	Fixes  []fixView
	Run    *store.Run
	Row    row
	KB     kb.Entry
	HasKB  bool
	Route  *source.Route
	Back   string
	Proxy  string // proxy de la route, pour ouvrir le bon correctif
	Others int    // autres hôtes touchés par le même contrôle
}

func (s *Server) issuePage(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	run, rows, err := s.state(r.Context(), s.runID(r.Context(), r.URL.Query().Get("passage")))
	if err != nil {
		s.fail(w, err)
		return
	}
	d := issueData{Run: run, Back: safeBack(r.URL.Query().Get("back"))}
	found := false
	for _, x := range rows {
		if x.Key == key {
			d.Row, found = x, true
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	for _, x := range rows {
		if x.Check == d.Row.Check && x.Key != key && inTab(x, "") {
			d.Others++
		}
	}
	d.KB, d.HasKB = kb.Lookup(d.Row.Check)
	// Onglets : le proxy, numéroté s'il revient plusieurs fois.
	count, seenN := map[string]int{}, map[string]int{}
	for _, f := range d.KB.Fixes {
		count[f.Proxy]++
	}
	for _, f := range d.KB.Fixes {
		tab := f.Proxy
		if count[f.Proxy] > 1 {
			seenN[f.Proxy]++
			tab = fmt.Sprintf("%s %d", f.Proxy, seenN[f.Proxy])
		}
		d.Fixes = append(d.Fixes, fixView{Tab: tab, Label: f.Label, Code: f.Code, Proxy: f.Proxy})
	}
	if routes := s.inventoryRoutes(r.Context()); routes != nil {
		for i := range routes {
			for _, h := range routes[i].Hosts {
				if strings.EqualFold(h, d.Row.Host) {
					d.Route = &routes[i]
				}
			}
		}
	}
	if d.Route != nil {
		d.Proxy = strings.SplitN(d.Route.Source, "/", 2)[0]
	}
	s.render(w, r, "issue", d.Row.Title, "issues", d)
}

// inventoryRoutes : routes du dernier passage complet.
func (s *Server) inventoryRoutes(ctx context.Context) []source.Route {
	runs, err := s.Store.Runs(ctx, 50)
	if err != nil {
		return nil
	}
	for _, run := range runs {
		if run.Scope == "" && (run.Status == "ok" || run.Status == "partial") {
			inv, err := s.Store.Inventory(ctx, run.ID)
			if err != nil || len(inv) == 0 {
				return nil
			}
			var routes []source.Route
			json.Unmarshal(inv, &routes)
			return routes
		}
	}
	return nil
}

// --- problèmes (par contrôle) ---

type problem struct {
	Check    string
	Title    string
	Severity check.Severity
	Items    []probItem
	New      int
	KB       kb.Entry
	HasKB    bool
}

type probItem struct {
	Target, Key string
	New         bool
}

func (s *Server) problemsPage(w http.ResponseWriter, r *http.Request) {
	f := parseFilter(r.URL.Query())
	f.Run = s.runID(r.Context(), f.Ref)
	_, rows, err := s.state(r.Context(), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	by := map[string]*problem{}
	for _, x := range rows {
		if !inTab(x, "") || !f.keep(x) {
			continue
		}
		p := by[x.Check]
		if p == nil {
			p = &problem{Check: x.Check, Title: x.Title, Severity: x.Severity}
			p.KB, p.HasKB = kb.Lookup(x.Check)
			// Famille dynamique (un contrôle par cookie, par lint…) : le titre de
			// l'écart est plus précis que celui de la famille.
			if p.HasKB && !strings.HasPrefix(x.Check, "http.cookie.") && !strings.HasPrefix(x.Check, "tls.cert.lint.") &&
				!strings.HasPrefix(x.Check, "port.risky.") && !strings.HasPrefix(x.Check, "http.leak.") {
				p.Title = p.KB.Title
			}
			by[x.Check] = p
		}
		if x.Severity > p.Severity {
			p.Severity = x.Severity
		}
		p.Items = append(p.Items, probItem{x.Target, x.Key, x.State == store.New})
		if x.State == store.New {
			p.New++
		}
	}
	var out []problem
	for _, p := range by {
		sort.Slice(p.Items, func(i, j int) bool { return p.Items[i].Target < p.Items[j].Target })
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if len(out[i].Items) != len(out[j].Items) {
			return len(out[i].Items) > len(out[j].Items)
		}
		return out[i].Check < out[j].Check
	})
	s.render(w, r, "problems", "Problèmes", "problems", struct {
		Problems []problem
		F        filter
	}{out, f})
}

// --- hôtes ---

func (s *Server) hostsPage(w http.ResponseWriter, r *http.Request) {
	_, rows, err := s.state(r.Context(), 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "hosts", "Hôtes", "hosts", s.hostRows(r.Context(), rows))
}

type hostData struct {
	H      hostRow
	Issues issuesData
	Route  []source.Route
}

func (s *Server) hostPage(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.PathValue("host"))
	q := r.URL.Query()
	q.Set("host", host)
	r.URL.RawQuery = q.Encode()
	d, err := s.issuesData(r, "/host/"+url.PathEscape(host))
	if err != nil {
		s.fail(w, err)
		return
	}
	_, rows, _ := s.state(r.Context(), 0)
	hd := hostData{Issues: d}
	for _, h := range s.hostRows(r.Context(), rows) {
		if h.Host == host {
			hd.H = h
		}
	}
	if hd.H.Host == "" {
		hd.H = hostRow{Host: host, Grade: "A", Score: 100}
	}
	for _, rt := range s.inventoryRoutes(r.Context()) {
		for _, h := range rt.Hosts {
			if strings.EqualFold(h, host) {
				hd.Route = append(hd.Route, rt)
			}
		}
	}
	s.render(w, r, "host", host, "hosts", hd)
}

// --- passages ---

func (s *Server) runsPage(w http.ResponseWriter, r *http.Request) {
	runs, err := s.Store.Runs(r.Context(), 100)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, r, "runs", "Passages", "runs", runs)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request) {
	id := s.runID(r.Context(), r.PathValue("ref"))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	run, err := s.Store.GetRun(r.Context(), id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	ds, err := s.Store.Compare(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	type item struct {
		check.Finding
		Issue    string            `json:"issue"`
		State    store.State       `json:"state"`
		Carried  bool              `json:"carried,omitempty"`
		Accepted *store.Acceptance `json:"accepted,omitempty"`
	}
	out := struct {
		Run      store.Run `json:"run"`
		Findings []item    `json:"findings"`
	}{Run: run, Findings: []item{}}
	for _, d := range ds {
		out.Findings = append(out.Findings, item{d.Finding, d.IssueKey(), d.State, d.Carried, d.Accepted})
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="vigie-%s.json"`, run.Started.Local().Format("2006-01-02-1504")))
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(out)
}

// Les passages se désignent par leur date de début, à la seconde, heure locale :
// un seul passage tourne à la fois, deux ne commencent pas la même seconde.
const refLayout = "20060102-150405"

func runRef(t time.Time) string { return t.Local().Format(refLayout) }

// runID retrouve le passage d'une date runRef ; 0 si absente ou inconnue.
func (s *Server) runID(ctx context.Context, ref string) int64 {
	t, err := time.ParseInLocation(refLayout, ref, time.Local)
	if err != nil {
		return 0
	}
	id, _ := s.Store.RunStartedAt(ctx, t)
	return id
}
