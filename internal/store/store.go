// Package store garde les passages, leurs constats et les écarts assumés dans SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS runs (
	id       INTEGER PRIMARY KEY,
	started  INTEGER NOT NULL,
	finished INTEGER,
	status   TEXT NOT NULL DEFAULT 'running', -- running, ok, partial, failed
	note     TEXT NOT NULL DEFAULT '',
	inventory TEXT NOT NULL DEFAULT '', -- routes découvertes (JSON), pour l'affichage
	measured  TEXT, -- unités mesurées (JSON, check.Unit) ; NULL = tout ce qui est connu
	scope     TEXT NOT NULL DEFAULT '' -- vide = passage complet, sinon l'hôte re-testé
);
CREATE TABLE IF NOT EXISTS analyses (
	run_id   INTEGER PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
	at       INTEGER NOT NULL,
	provider TEXT NOT NULL,
	masked   INTEGER NOT NULL,
	text     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
	run_id     INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
	key        TEXT NOT NULL,
	check_id   TEXT NOT NULL,
	target     TEXT NOT NULL,
	vantage    TEXT NOT NULL,
	privileged INTEGER NOT NULL,
	severity   INTEGER NOT NULL,
	title      TEXT NOT NULL,
	evidence   TEXT NOT NULL,
	issue      TEXT NOT NULL DEFAULT '', -- check.IssueKey : écart tous points de vue confondus
	PRIMARY KEY (run_id, key)
);
CREATE TABLE IF NOT EXISTS targets (
	id    INTEGER PRIMARY KEY,
	host  TEXT NOT NULL,
	ports TEXT NOT NULL,
	note  TEXT NOT NULL,
	added INTEGER NOT NULL,
	UNIQUE (host, ports)
);
CREATE TABLE IF NOT EXISTS acceptances (
	key    TEXT PRIMARY KEY, -- check.IssueKey : l'écart d'un hôte, tous points de vue
	note   TEXT NOT NULL,
	author TEXT NOT NULL,
	at     INTEGER NOT NULL
);`

type Store struct {
	db *sql.DB

	// Cache de Compare : un passage terminé ne change plus, seules les écritures
	// (constats, acceptations, état) l'invalident, d'où une génération globale.
	mu     sync.Mutex
	gen    uint64
	cache  map[int64]cmpEntry
	memo   map[string]memoEntry
	lastDV int64 // PRAGMA data_version : change quand un autre processus écrit
}

// sync invalide le cache si un autre processus (« vigie scan ») a écrit la base.
func (s *Store) sync() {
	var dv int64
	if err := s.db.QueryRow(`PRAGMA data_version`).Scan(&dv); err != nil {
		s.touch()
		return
	}
	s.mu.Lock()
	if dv != s.lastDV {
		s.lastDV = dv
		s.gen++
	}
	s.mu.Unlock()
}

// memo garde le dernier résultat d'une lecture tant qu'aucune écriture n'a eu
// lieu ; les passages en cours (autre processus possible) ne sont pas mémorisés.
type memoEntry struct {
	gen uint64
	val any
}

func (s *Store) memoGet(key string) (any, bool) {
	s.sync()
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.memo[key]
	if !ok || e.gen != s.gen {
		return nil, false
	}
	return e.val, true
}

func (s *Store) memoSet(key string, gen uint64, v any) {
	s.mu.Lock()
	s.memo[key] = memoEntry{gen, v}
	s.mu.Unlock()
}

func (s *Store) curGen() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

type cmpEntry struct {
	gen    uint64
	deltas []Delta
}

// touch invalide le cache de comparaison ; chaque écriture l'appelle.
func (s *Store) touch() {
	s.mu.Lock()
	s.gen++
	s.mu.Unlock()
}

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // un seul écrivain SQLite, évite SQLITE_BUSY
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schéma : %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration : %w", err)
	}
	// Un passage resté « running » depuis plus de 12 h vient d'un arrêt brutal. Plus
	// récent, il peut tourner dans un autre processus (« vigie scan » lancé à côté
	// du serveur) : on n'y touche pas.
	if _, err := db.Exec(`UPDATE runs SET status='failed', note='interrompu (arrêt de vigie)', finished=started
		WHERE status='running' AND started < ?`, time.Now().Add(-12*time.Hour).Unix()); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, cache: map[int64]cmpEntry{}, memo: map[string]memoEntry{}}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func renameVantage(db *sql.DB) error {
	rows, err := db.Query(`SELECT run_id, key, check_id, target FROM findings
		WHERE vantage = 'dns' AND (check_id LIKE 'http.%' OR check_id LIKE 'tls.%' OR check_id LIKE 'parity.%')`)
	if err != nil {
		return err
	}
	type row struct {
		run          int64
		key, ck, tgt string
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.run, &r.key, &r.ck, &r.tgt); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if len(todo) == 0 {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range todo {
		k := check.Finding{Check: r.ck, Target: r.tgt, Vantage: "public"}.Key()
		if _, err := tx.Exec(`UPDATE OR IGNORE findings SET vantage='public', key=? WHERE run_id=? AND key=?`, k, r.run, r.key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// migrate ajoute aux bases déjà créées les colonnes venues après coup.
func migrate(db *sql.DB) error {
	has := func(table, col string) (bool, error) {
		rows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return false, err
			}
			if n == col {
				return true, nil
			}
		}
		return false, rows.Err()
	}
	for _, c := range []struct{ table, col, def string }{
		{"runs", "measured", "TEXT"},
		{"runs", "scope", "TEXT NOT NULL DEFAULT ''"},
		{"findings", "issue", "TEXT NOT NULL DEFAULT ''"},
	} {
		ok, err := has(c.table, c.col)
		if err != nil {
			return err
		}
		if !ok {
			if _, err := db.Exec(`ALTER TABLE ` + c.table + ` ADD COLUMN ` + c.col + ` ` + c.def); err != nil {
				return err
			}
		}
	}
	// Les mesures HTTP, TLS et de parité s'appelaient « dns » avant le point de vue
	// « public » : on les renomme, clé comprise, pour ne pas les voir « nouvelles ».
	if err := renameVantage(db); err != nil {
		return err
	}
	// Clé d'écart des constats enregistrés avant son introduction.
	rows, err := db.Query(`SELECT run_id, key, check_id, target FROM findings WHERE issue = ''`)
	if err != nil {
		return err
	}
	type row struct {
		run          int64
		key, ck, tgt string
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.run, &r.key, &r.ck, &r.tgt); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, r := range todo {
		if _, err := tx.Exec(`UPDATE findings SET issue=? WHERE run_id=? AND key=?`,
			check.Finding{Check: r.ck, Target: r.tgt}.IssueKey(), r.run, r.key); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) BeginRun(ctx context.Context, at time.Time) (int64, error) {
	s.touch()
	r, err := s.db.ExecContext(ctx, `INSERT INTO runs(started) VALUES (?)`, at.Unix())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

// SaveFindings enregistre les constats d'un passage ; un doublon de clé garde le premier.
func (s *Store) SaveFindings(ctx context.Context, run int64, fs []check.Finding) error {
	s.touch()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, f := range fs {
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO findings(run_id, key, check_id, target, vantage, privileged, severity, title, evidence, issue)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			run, f.Key(), f.Check, f.Target, f.Vantage, f.Privileged, int(f.Severity), f.Title, f.Evidence, f.IssueKey())
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) FinishRun(ctx context.Context, run int64, at time.Time, status, note string) error {
	s.touch()
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET finished=?, status=?, note=? WHERE id=?`, at.Unix(), status, note, run)
	return err
}

type Acceptance struct {
	Note, Author string
	At           time.Time
}

func (s *Store) Accept(ctx context.Context, key, note, author string, at time.Time) error {
	s.touch()
	_, err := s.db.ExecContext(ctx, `INSERT INTO acceptances VALUES (?,?,?,?)
		ON CONFLICT(key) DO UPDATE SET note=excluded.note, author=excluded.author, at=excluded.at`,
		key, note, author, at.Unix())
	return err
}

func (s *Store) Unaccept(ctx context.Context, key string) error {
	s.touch()
	_, err := s.db.ExecContext(ctx, `DELETE FROM acceptances WHERE key=?`, key)
	return err
}

type State string

const (
	New       State = "nouveau"
	Resolved  State = "résolu"
	Unchanged State = "inchangé"
)

type Delta struct {
	check.Finding
	State    State
	Accepted *Acceptance
	Carried  bool // repris d'un passage antérieur : ce passage (partiel ou ciblé) ne l'a pas re-mesuré
}

// SetMeasured enregistre les unités (check.Unit) que le passage a réellement
// mesurées ; un passage sans cette liste est réputé avoir tout mesuré.
func (s *Store) SetMeasured(ctx context.Context, run int64, units []string) error {
	s.touch()
	b, err := json.Marshal(units)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE runs SET measured=? WHERE id=?`, string(b), run)
	return err
}

type pastRun struct {
	id       int64
	scoped   bool            // re-test d'un hôte : ne conclut rien sur les autres
	measured map[string]bool // nil = tout
	findings map[string]Delta
}

func (p *pastRun) covers(unit string) bool { return p.measured == nil || p.measured[unit] }

func (s *Store) loadRun(ctx context.Context, id int64) (*pastRun, string, error) {
	var status, scope string
	var measured sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT status, measured, scope FROM runs WHERE id=?`, id).Scan(&status, &measured, &scope); err != nil {
		return nil, "", err
	}
	p := &pastRun{id: id, scoped: scope != "", findings: map[string]Delta{}}
	if measured.Valid && measured.String != "" {
		var units []string
		if err := json.Unmarshal([]byte(measured.String), &units); err != nil {
			return nil, "", err
		}
		p.measured = map[string]bool{}
		for _, u := range units {
			p.measured[u] = true
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT f.key, f.check_id, f.target, f.vantage, f.privileged, f.severity, f.title, f.evidence,
		a.note, a.author, a.at FROM findings f LEFT JOIN acceptances a ON a.key = f.issue WHERE f.run_id = ?`, id)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	for rows.Next() {
		var d Delta
		var key string
		var note, author sql.NullString
		var at sql.NullInt64
		if err := rows.Scan(&key, &d.Check, &d.Target, &d.Vantage, &d.Privileged, &d.Severity, &d.Title, &d.Evidence,
			&note, &author, &at); err != nil {
			return nil, "", err
		}
		if note.Valid {
			d.Accepted = &Acceptance{note.String, author.String, time.Unix(at.Int64, 0)}
		}
		p.findings[key] = d
	}
	return p, status, rows.Err()
}

// compareWindow : passages antérieurs consultés pour retrouver la dernière
// mesure d'une unité qu'un passage partiel a sautée.
const compareWindow = 10

// Compare donne les constats du passage run face, unité par unité, au dernier
// passage qui a mesuré cette unité : nouveaux, inchangés, résolus. Un passage
// partiel ou ciblé ne déclare rien résolu sur une unité qu'il n'a pas mesurée :
// ses anciens constats sont repris tels quels (Carried).
func (s *Store) Compare(ctx context.Context, run int64) ([]Delta, error) {
	s.sync()
	s.mu.Lock()
	gen := s.gen
	if e, ok := s.cache[run]; ok && e.gen == gen {
		s.mu.Unlock()
		return append([]Delta(nil), e.deltas...), nil
	}
	s.mu.Unlock()
	out, status, err := s.compare(ctx, run)
	if err == nil && status != "running" { // un passage en cours (peut-être dans un autre processus) change encore
		s.mu.Lock()
		if len(s.cache) > 64 { // borne la mémoire : on repart de zéro
			s.cache = map[int64]cmpEntry{}
		}
		s.cache[run] = cmpEntry{gen: gen, deltas: out}
		s.mu.Unlock()
		out = append([]Delta(nil), out...)
	}
	return out, err
}

func (s *Store) compare(ctx context.Context, run int64) ([]Delta, string, error) {
	cur, status, err := s.loadRun(ctx, run)
	if err != nil {
		return nil, "", err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM runs WHERE id < ? AND status IN ('ok','partial') ORDER BY id DESC LIMIT ?`, run, compareWindow)
	if err != nil {
		return nil, "", err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, "", err
		}
		ids = append(ids, id)
	}
	rows.Close()
	var prior []*pastRun
	for _, id := range ids {
		p, _, err := s.loadRun(ctx, id)
		if err != nil {
			return nil, "", err
		}
		prior = append(prior, p)
	}
	latestFor := func(unit string) *pastRun {
		for _, p := range prior {
			if p.covers(unit) {
				return p
			}
		}
		return nil
	}
	// Ports : un changement ne compte qu'une fois confirmé par deux passages (un
	// port filtré ou lent bascule d'un passage à l'autre). secondFor donne le
	// passage d'avant le dernier qui a mesuré l'unité.
	secondFor := func(unit string) *pastRun {
		seen := false
		for _, p := range prior {
			if p.covers(unit) {
				if seen {
					return p
				}
				seen = true
			}
		}
		return nil
	}
	in := func(p *pastRun, key string) bool {
		if p == nil {
			return false
		}
		_, ok := p.findings[key]
		return ok
	}

	var out []Delta
	for key, d := range cur.findings {
		d.State = New
		unit := check.Unit(d.Target)
		if in(latestFor(unit), key) || (isPort(d.Check) && in(secondFor(unit), key)) {
			d.State = Unchanged // revenu après une seule absence : rien n'a changé
		}
		out = append(out, d)
	}
	seen := map[string]bool{}
	for i, p := range prior {
		for key, d := range p.findings {
			if seen[key] {
				continue
			}
			seen[key] = true
			if _, still := cur.findings[key]; still {
				continue
			}
			unit := check.Unit(d.Target)
			if isPort(d.Check) && cur.covers(unit) {
				switch {
				case latestFor(unit) == p:
					d.State = Unchanged // première absence : à confirmer au passage suivant
				case secondFor(unit) == p && !in(latestFor(unit), key):
					d.State = Resolved // absent deux passages de suite
				default:
					continue
				}
				out = append(out, d)
				continue
			}
			if latestFor(unit) != p {
				continue // une mesure plus récente de cette unité fait foi
			}
			switch {
			case cur.covers(unit):
				d.State = Resolved
			case status == "partial" || cur.scoped:
				d.State, d.Carried = Unchanged, true
			case i == 0:
				d.State = Resolved // passage complet : l'unité a disparu de l'inventaire
			default:
				continue
			}
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		if a.Check != b.Check {
			return a.Check < b.Check
		}
		return a.Vantage < b.Vantage
	})
	return out, status, nil
}

// Target est une cible saisie à la main ; la validation est faite par source/manual.
type Target struct {
	ID    int64
	Host  string
	Ports []int
	Note  string
	Added time.Time
}

func (s *Store) AddTarget(ctx context.Context, t Target) (int64, error) {
	ports := make([]string, len(t.Ports))
	for i, p := range t.Ports {
		ports[i] = strconv.Itoa(p)
	}
	r, err := s.db.ExecContext(ctx, `INSERT INTO targets(host, ports, note, added) VALUES (?,?,?,?)`,
		t.Host, strings.Join(ports, ","), t.Note, t.Added.Unix())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) DeleteTarget(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM targets WHERE id=?`, id)
	return err
}

func (s *Store) Targets(ctx context.Context) ([]Target, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, host, ports, note, added FROM targets ORDER BY host, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		var ports string
		var added int64
		if err := rows.Scan(&t.ID, &t.Host, &ports, &t.Note, &added); err != nil {
			return nil, err
		}
		for _, p := range strings.Split(ports, ",") {
			if n, err := strconv.Atoi(p); err == nil {
				t.Ports = append(t.Ports, n)
			}
		}
		t.Added = time.Unix(added, 0)
		out = append(out, t)
	}
	return out, rows.Err()
}

type Run struct {
	ID               int64
	Started          time.Time
	Finished         time.Time // zéro tant que le passage tourne
	Status, Note     string
	Scope            string // vide = passage complet, sinon l'hôte re-testé
	Findings, Issues int    // constats ; écarts (tous points de vue confondus) non assumés de sévérité ≥ faible
}

// RunStartedAt : le passage commencé à cette seconde.
func (s *Store) RunStartedAt(ctx context.Context, t time.Time) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `SELECT id FROM runs WHERE started=? ORDER BY id DESC LIMIT 1`, t.Unix()).Scan(&id)
	return id, err
}

func (s *Store) SetScope(ctx context.Context, run int64, scope string) error {
	s.touch()
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET scope=? WHERE id=?`, scope, run)
	return err
}

func (s *Store) SetInventory(ctx context.Context, run int64, inventory []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE runs SET inventory=? WHERE id=?`, string(inventory), run)
	return err
}

func (s *Store) Inventory(ctx context.Context, run int64) ([]byte, error) {
	var inv string
	err := s.db.QueryRowContext(ctx, `SELECT inventory FROM runs WHERE id=?`, run).Scan(&inv)
	return []byte(inv), err
}

const runCols = `r.id, r.started, coalesce(r.finished, 0), r.status, r.note, r.scope,
	(SELECT count(*) FROM findings f WHERE f.run_id = r.id),
	(SELECT count(DISTINCT f.issue) FROM findings f WHERE f.run_id = r.id AND f.severity > 0
		AND NOT EXISTS (SELECT 1 FROM acceptances a WHERE a.key = f.issue))`

func scanRun(sc interface{ Scan(...any) error }) (Run, error) {
	var r Run
	var started, finished int64
	err := sc.Scan(&r.ID, &started, &finished, &r.Status, &r.Note, &r.Scope, &r.Findings, &r.Issues)
	r.Started = time.Unix(started, 0)
	if finished > 0 {
		r.Finished = time.Unix(finished, 0)
	}
	return r, err
}

// Runs renvoie les derniers passages, du plus récent au plus ancien.
func (s *Store) Runs(ctx context.Context, limit int) ([]Run, error) {
	key := "runs:" + strconv.Itoa(limit)
	if v, ok := s.memoGet(key); ok {
		return append([]Run(nil), v.([]Run)...), nil
	}
	gen := s.curGen()
	out, err := s.runs(ctx, limit)
	if err == nil && (len(out) == 0 || out[0].Status != "running") {
		s.memoSet(key, gen, out)
		out = append([]Run(nil), out...)
	}
	return out, err
}

func (s *Store) runs(ctx context.Context, limit int) ([]Run, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+runCols+` FROM runs r ORDER BY r.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun renvoie sql.ErrNoRows si le passage n'existe pas.
func (s *Store) GetRun(ctx context.Context, id int64) (Run, error) {
	return scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM runs r WHERE r.id = ?`, id))
}

func (s *Store) Setting(ctx context.Context, key, def string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	return v, err
}

func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// InTab dit si un écart appartient à un onglet d'état : "" = ouverts (nouveaux et
// toujours là, non assumés), "nouveau", "inchangé", "résolu", "assumé", "tout".
func (d Delta) InTab(tab string) bool {
	accepted := d.Accepted != nil && d.State != Resolved
	switch tab {
	case "":
		return d.State != Resolved && !accepted
	case "nouveau", "inchangé":
		return string(d.State) == tab && !accepted
	case "résolu":
		return d.State == Resolved
	case "assumé":
		return accepted
	}
	return true
}

type Analysis struct {
	At       time.Time
	Provider string
	Masked   bool
	Text     string
}

func (s *Store) SaveAnalysis(ctx context.Context, run int64, a Analysis) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO analyses VALUES (?,?,?,?,?)
		ON CONFLICT(run_id) DO UPDATE SET at=excluded.at, provider=excluded.provider, masked=excluded.masked, text=excluded.text`,
		run, a.At.Unix(), a.Provider, a.Masked, a.Text)
	return err
}

// GetAnalysis renvoie sql.ErrNoRows si le passage n'a pas d'analyse.
func (s *Store) GetAnalysis(ctx context.Context, run int64) (Analysis, error) {
	var a Analysis
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT at, provider, masked, text FROM analyses WHERE run_id=?`, run).
		Scan(&at, &a.Provider, &a.Masked, &a.Text)
	a.At = time.Unix(at, 0)
	return a, err
}

// VantageResult : ce qu'un point de vue a vu d'un écart.
type VantageResult struct {
	Name       string
	State      State
	Privileged bool
	Evidence   string
}

// Issue : un écart (contrôle, cible), tous points de vue confondus.
type Issue struct {
	Key, Check, Target, Title string
	Severity                  check.Severity // la plus haute des points de vue
	State                     State          // nouveau si un point de vue l'est, résolu si tous le sont
	Carried                   bool           // aucun point de vue re-mesuré par ce passage
	Privileged                bool           // tous les points de vue qui le voient sont privilégiés
	Vantages                  []VantageResult
	Accepted                  *Acceptance
}

// Group regroupe les constats par écart, dans l'ordre de ds.
func Group(ds []Delta) []Issue {
	idx := map[string]int{}
	var out []Issue
	for _, d := range ds {
		k := d.IssueKey()
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, Issue{Key: k, Check: d.Check, Target: d.Target, Title: d.Title, Severity: d.Severity,
				State: Resolved, Carried: true, Privileged: true, Accepted: d.Accepted})
		}
		is := &out[i]
		is.Vantages = append(is.Vantages, VantageResult{Name: d.Vantage, State: d.State, Privileged: d.Privileged, Evidence: d.Evidence})
		if d.State != Resolved {
			if d.Severity > is.Severity || is.State == Resolved {
				is.Severity, is.Title = d.Severity, d.Title
			}
			is.Privileged = is.Privileged && d.Privileged
			is.Carried = is.Carried && d.Carried
			if d.State == New || is.State == Resolved {
				is.State = d.State
			}
		}
	}
	for i := range out {
		if out[i].State == Resolved {
			out[i].Privileged, out[i].Carried = false, false
		}
		sort.Slice(out[i].Vantages, func(a, b int) bool {
			return vantageRank(out[i].Vantages[a].Name) < vantageRank(out[i].Vantages[b].Name)
		})
	}
	return out
}

func vantageRank(v string) int {
	switch v {
	case "public":
		return 0
	case "dns":
		return 1
	case "origine":
		return 2
	case "interne":
		return 3
	case "inconnu":
		return 4
	}
	return 5
}

// UnitCount : écarts ouverts (sévérité ≥ faible, non assumés) d'une unité lors d'un passage.
type UnitCount struct {
	Run   int64
	At    time.Time
	Unit  string
	Count int
}

// IssueCounts rend, pour les derniers passages complets terminés (du plus ancien
// au plus récent), le nombre d'écarts ouverts par unité : tendances globale et par hôte.
func (s *Store) IssueCounts(ctx context.Context, runs int) ([]UnitCount, error) {
	key := "counts:" + strconv.Itoa(runs)
	if v, ok := s.memoGet(key); ok {
		return v.([]UnitCount), nil
	}
	gen := s.curGen()
	out, err := s.issueCounts(ctx, runs)
	if err == nil {
		s.memoSet(key, gen, out)
	}
	return out, err
}

func (s *Store) issueCounts(ctx context.Context, runs int) ([]UnitCount, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.started, f.target, count(DISTINCT f.issue)
		FROM (SELECT id, started FROM runs WHERE status IN ('ok','partial') AND scope = '' ORDER BY id DESC LIMIT ?) r
		JOIN findings f ON f.run_id = r.id
		WHERE f.severity > 0 AND NOT EXISTS (SELECT 1 FROM acceptances a WHERE a.key = f.issue)
		GROUP BY r.id, f.target ORDER BY r.id`, runs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agg := map[[2]string]*UnitCount{}
	var order []*UnitCount
	for rows.Next() {
		var id, at int64
		var target string
		var n int
		if err := rows.Scan(&id, &at, &target, &n); err != nil {
			return nil, err
		}
		u := check.Unit(target)
		k := [2]string{strconv.FormatInt(id, 10), u}
		c := agg[k]
		if c == nil {
			c = &UnitCount{Run: id, At: time.Unix(at, 0), Unit: u}
			agg[k] = c
			order = append(order, c)
		}
		c.Count += n
	}
	out := make([]UnitCount, len(order))
	for i, c := range order {
		out[i] = *c
	}
	return out, rows.Err()
}

// GetAcceptance rend l'acceptation d'une clé, ou nil.
func (s *Store) GetAcceptance(ctx context.Context, key string) (*Acceptance, error) {
	var a Acceptance
	var at int64
	err := s.db.QueryRowContext(ctx, `SELECT note, author, at FROM acceptances WHERE key=?`, key).Scan(&a.Note, &a.Author, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	a.At = time.Unix(at, 0)
	return &a, err
}

func isPort(id string) bool { return strings.HasPrefix(id, "port.") }
