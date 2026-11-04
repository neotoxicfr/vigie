package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
)

func TestCompare(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Unix(1_800_000_000, 0)

	hsts := check.Finding{Check: "http.hsts", Target: "a.example.com", Vantage: "dns", Severity: check.Medium, Evidence: "absent"}
	csp := check.Finding{Check: "http.csp", Target: "a.example.com", Vantage: "dns", Severity: check.Low}
	tls10 := check.Finding{Check: "tls.version", Target: "a.example.com", Vantage: "origine", Severity: check.High}
	cookie := check.Finding{Check: "http.cookie", Target: "b.example.com", Vantage: "dns"}

	r1, _ := s.BeginRun(ctx, now)
	if err := s.SaveFindings(ctx, r1, []check.Finding{hsts, csp, tls10}); err != nil {
		t.Fatal(err)
	}
	s.FinishRun(ctx, r1, now, "ok", "")

	// Un passage échoué entre les deux ne sert pas de référence.
	rf, _ := s.BeginRun(ctx, now)
	s.FinishRun(ctx, rf, now, "failed", "source injoignable")

	r2, _ := s.BeginRun(ctx, now)
	hsts.Evidence = "max-age=0" // preuve changée, même constat
	if err := s.SaveFindings(ctx, r2, []check.Finding{hsts, csp, cookie}); err != nil {
		t.Fatal(err)
	}
	s.FinishRun(ctx, r2, now, "ok", "")
	if err := s.Accept(ctx, csp.IssueKey(), "CSP imposée par l'appli", "neo", now); err != nil {
		t.Fatal(err)
	}

	ds, err := s.Compare(ctx, r2)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Delta{}
	for _, d := range ds {
		got[d.Check] = d
	}
	want := map[string]State{"http.hsts": Unchanged, "http.csp": Unchanged, "http.cookie": New, "tls.version": Resolved}
	if len(got) != len(want) {
		t.Fatalf("%d deltas, attendu %d : %+v", len(got), len(want), ds)
	}
	for c, st := range want {
		if got[c].State != st {
			t.Errorf("%s : %s, attendu %s", c, got[c].State, st)
		}
	}
	if got["http.hsts"].Evidence != "max-age=0" {
		t.Errorf("preuve du passage courant attendue, reçu %q", got["http.hsts"].Evidence)
	}
	if a := got["http.csp"].Accepted; a == nil || a.Author != "neo" {
		t.Errorf("csp devrait être assumé : %+v", a)
	}
	if got["http.cookie"].Accepted != nil {
		t.Error("cookie ne devrait pas être assumé")
	}

	// Premier passage : tout est nouveau.
	ds, _ = s.Compare(ctx, r1)
	for _, d := range ds {
		if d.State != New {
			t.Errorf("premier passage : %s en %s", d.Check, d.State)
		}
	}
}

func TestRunsAndSettings(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	r1, _ := s.BeginRun(ctx, now)
	f := check.Finding{Check: "a", Target: "t", Vantage: "dns", Severity: check.Medium}
	i := check.Finding{Check: "b", Target: "t", Vantage: "dns", Severity: check.Info}
	acc := check.Finding{Check: "c", Target: "t", Vantage: "dns", Severity: check.High}
	s.SaveFindings(ctx, r1, []check.Finding{f, i, acc})
	s.Accept(ctx, acc.IssueKey(), "voulu", "neo", now)
	s.SetInventory(ctx, r1, []byte(`[{"name":"x"}]`))
	s.FinishRun(ctx, r1, now.Add(time.Minute), "ok", "")
	r2, _ := s.BeginRun(ctx, time.Now().Add(-13*time.Hour)) // laissé « running » depuis 13 h : arrêt brutal
	fresh, _ := s.BeginRun(ctx, time.Now())                 // en cours dans un autre processus : intact
	s.Close()

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	runs, err := s.Runs(ctx, 10)
	if err != nil || len(runs) != 3 {
		t.Fatalf("runs : %v %+v", err, runs)
	}
	if runs[0].ID != fresh || runs[0].Status != "running" {
		t.Errorf("passage récent touché : %+v", runs[0])
	}
	if runs[1].ID != r2 || runs[1].Status != "failed" {
		t.Errorf("passage interrompu non marqué : %+v", runs[1])
	}
	if r := runs[2]; r.Findings != 3 || r.Issues != 1 || r.Finished.IsZero() {
		t.Errorf("compteurs : %+v (attendu 3 constats, 1 écart non assumé)", r)
	}
	if _, err := s.GetRun(ctx, 999); err == nil {
		t.Error("passage inexistant trouvé")
	}
	if inv, _ := s.Inventory(ctx, r1); string(inv) != `[{"name":"x"}]` {
		t.Errorf("inventaire : %s", inv)
	}
	if v, _ := s.Setting(ctx, "cadence", "0"); v != "0" {
		t.Errorf("défaut : %q", v)
	}
	s.SetSetting(ctx, "cadence", "24h")
	s.SetSetting(ctx, "cadence", "168h")
	if v, _ := s.Setting(ctx, "cadence", "0"); v != "168h" {
		t.Errorf("réglage : %q", v)
	}
}

func TestAnalysis(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(filepath.Join(t.TempDir(), "v.db"))
	defer s.Close()
	id, _ := s.BeginRun(ctx, time.Now())
	if _, err := s.GetAnalysis(ctx, id); err == nil {
		t.Fatal("analyse trouvée avant enregistrement")
	}
	s.SaveAnalysis(ctx, id, Analysis{At: time.Unix(1, 0), Provider: "anthropic", Masked: true, Text: "v1"})
	s.SaveAnalysis(ctx, id, Analysis{At: time.Unix(2, 0), Provider: "anthropic", Masked: false, Text: "v2"})
	a, err := s.GetAnalysis(ctx, id)
	if err != nil || a.Text != "v2" || a.Masked {
		t.Errorf("analyse : %+v %v", a, err)
	}
}

// Un passage partiel (source en panne) ne déclare pas « résolu » ce qu'il n'a
// pas mesuré, et le passage complet suivant ne le refait pas passer en « nouveau ».
func TestComparePartial(t *testing.T) {
	ctx := context.Background()
	s, _ := Open(filepath.Join(t.TempDir(), "v.db"))
	defer s.Close()
	now := time.Now()
	fa := check.Finding{Check: "http.hsts.absent", Target: "a.example.com:443", Vantage: "dns", Severity: check.Medium}
	fb := check.Finding{Check: "http.csp.absent", Target: "b.example.com:443", Vantage: "dns", Severity: check.Medium}
	pass := func(status string, units []string, fs ...check.Finding) int64 {
		id, _ := s.BeginRun(ctx, now)
		s.SaveFindings(ctx, id, fs)
		s.SetMeasured(ctx, id, units)
		s.FinishRun(ctx, id, now, status, "")
		return id
	}
	states := func(id int64) map[string]State {
		ds, err := s.Compare(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]State{}
		for _, d := range ds {
			m[d.Check] = d.State
		}
		return m
	}
	pass("ok", []string{"a.example.com", "b.example.com"}, fa, fb)
	r2 := pass("partial", []string{"a.example.com"}, fa)
	if st := states(r2); st["http.csp.absent"] != Unchanged || st["http.hsts.absent"] != Unchanged {
		t.Errorf("passage partiel : %v", st)
	}
	r3 := pass("ok", []string{"a.example.com", "b.example.com"}, fa, fb)
	if st := states(r3); st["http.csp.absent"] != Unchanged {
		t.Errorf("après le partiel, b redevient %v au lieu d'inchangé", st)
	}
	r4 := pass("ok", []string{"a.example.com"}, fa) // b retiré de l'inventaire
	if st := states(r4); st["http.csp.absent"] != Resolved {
		t.Errorf("hôte retiré : %v", st)
	}
	r5 := pass("ok", []string{"a.example.com"}, fa)
	if st := states(r5); len(st) != 1 {
		t.Errorf("le résolu ne doit apparaître qu'une fois : %v", st)
	}
}

func TestGroup(t *testing.T) {
	mk := func(v string, st State, sev check.Severity, priv bool) Delta {
		return Delta{Finding: check.Finding{Check: "http.hsts.absent", Target: "a.example.com:443", Vantage: v, Severity: sev, Title: v, Privileged: priv}, State: st}
	}
	is := Group([]Delta{mk("interne", Unchanged, check.Low, true), mk("public", New, check.Medium, true), mk("origine", Resolved, check.High, false)})
	if len(is) != 1 {
		t.Fatalf("%d écarts", len(is))
	}
	g := is[0]
	if g.State != New || g.Severity != check.Medium || g.Title != "public" || !g.Privileged || len(g.Vantages) != 3 || g.Vantages[0].Name != "public" {
		t.Errorf("écart : %+v", g)
	}
	if r := Group([]Delta{mk("public", Resolved, check.Low, false)}); r[0].State != Resolved {
		t.Errorf("résolu : %+v", r[0])
	}
}

// Une base créée avant la clé d'écart est migrée à l'ouverture.
func TestMigrateOldSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE runs (id INTEGER PRIMARY KEY, started INTEGER NOT NULL, finished INTEGER, status TEXT NOT NULL DEFAULT 'running', note TEXT NOT NULL DEFAULT '', inventory TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE findings (run_id INTEGER NOT NULL, key TEXT NOT NULL, check_id TEXT NOT NULL, target TEXT NOT NULL, vantage TEXT NOT NULL, privileged INTEGER NOT NULL, severity INTEGER NOT NULL, title TEXT NOT NULL, evidence TEXT NOT NULL, PRIMARY KEY (run_id, key))`,
		`INSERT INTO runs(id, started, finished, status) VALUES (1, 1, 2, 'ok')`,
		`INSERT INTO findings VALUES (1, 'k', 'http.hsts.absent', 'a.example.com:443', 'dns', 0, 2, 't', '')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	want := check.Finding{Check: "http.hsts.absent", Target: "a.example.com:443"}.IssueKey()
	if err := s.Accept(context.Background(), want, "voulu", "neo", time.Now()); err != nil {
		t.Fatal(err)
	}
	ds, err := s.Compare(context.Background(), 1)
	if err != nil || len(ds) != 1 || ds[0].Accepted == nil {
		t.Fatalf("après migration : %+v %v", ds, err)
	}
}

func TestRenameDNSVantage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	s, _ := Open(path)
	ctx := context.Background()
	id, _ := s.BeginRun(ctx, time.Now())
	s.SaveFindings(ctx, id, []check.Finding{
		{Check: "http.hsts.absent", Target: "a.example.com:443", Vantage: "dns", Severity: check.Medium},
		{Check: "dns.caa.absent", Target: "example.com", Vantage: "dns", Severity: check.Low},
	})
	s.FinishRun(ctx, id, time.Now(), "ok", "")
	s.Close()
	s, _ = Open(path)
	defer s.Close()
	ds, _ := s.Compare(ctx, id)
	got := map[string]string{}
	for _, d := range ds {
		got[d.Check] = d.Vantage
		if d.Key() != d.Finding.Key() {
			t.Error("clé incohérente")
		}
	}
	if got["http.hsts.absent"] != "public" || got["dns.caa.absent"] != "dns" {
		t.Errorf("renommage : %v", got)
	}
}

// Un autre processus (« vigie scan ») qui écrit la base invalide le cache.
func TestCacheSeesOtherProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v.db")
	a, _ := Open(path)
	defer a.Close()
	ctx := context.Background()
	if runs, _ := a.Runs(ctx, 10); len(runs) != 0 {
		t.Fatal("base vide attendue")
	}
	b, _ := Open(path) // deuxième connexion, comme un autre processus
	id, _ := b.BeginRun(ctx, time.Now())
	b.FinishRun(ctx, id, time.Now(), "ok", "")
	b.Close()
	if runs, _ := a.Runs(ctx, 10); len(runs) != 1 {
		t.Errorf("écriture d'un autre processus invisible : %d passages", len(runs))
	}
}

// Un port qui bascule d'un passage à l'autre ne passe ni « résolu » ni
// « nouveau » : il faut deux passages de suite pour confirmer une disparition.
func TestComparePortNeedsTwoRuns(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Unix(1_800_000_000, 0)
	port := check.Finding{Check: "port.open", Target: "192.0.2.1:443", Vantage: "vpn"}
	hdr := check.Finding{Check: "http.hsts", Target: "192.0.2.1:443", Vantage: "vpn"}
	state := func(present bool) (State, State) {
		t.Helper()
		fs := []check.Finding{}
		if present {
			fs = append(fs, port, hdr)
		}
		r, _ := s.BeginRun(ctx, now)
		s.SaveFindings(ctx, r, fs)
		s.FinishRun(ctx, r, now, "ok", "")
		ds, _ := s.Compare(ctx, r)
		var p, h State
		for _, d := range ds {
			switch d.Check {
			case port.Check:
				p = d.State
			case hdr.Check:
				h = d.State
			}
		}
		return p, h
	}
	for i, c := range []struct {
		present  bool
		port, hd State
	}{
		{true, New, New},
		{false, Unchanged, Resolved}, // première absence : le port attend confirmation, l'en-tête non
		{true, Unchanged, New},       // revenu : rien n'a changé pour le port
		{false, Unchanged, Resolved},
		{false, Resolved, ""}, // deuxième absence : confirmé
		{false, "", ""},
	} {
		p, h := state(c.present)
		if p != c.port || h != c.hd {
			t.Errorf("passage %d : port %q en-tête %q, attendu %q %q", i+1, p, h, c.port, c.hd)
		}
	}
}
