package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/ai"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

func (s *Server) startRun(w http.ResponseWriter, r *http.Request) {
	to := safeBack(r.PostFormValue("back"))
	if _, err := s.Runner.Start(); err != nil {
		s.back(w, r, to, "err", err.Error())
		return
	}
	s.back(w, r, to, "ok", "Passage lancé.")
}

func (s *Server) retest(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(strings.TrimSpace(r.PostFormValue("host")))
	to := safeBack(r.PostFormValue("back"))
	if host == "" || len(host) > 253 {
		s.back(w, r, to, "err", "Hôte invalide.")
		return
	}
	if _, err := s.Runner.StartHost(host); err != nil {
		s.back(w, r, to, "err", err.Error())
		return
	}
	s.back(w, r, to, "ok", "Re-test de "+host+" lancé.")
}

// accept : portée « host » = cet écart (contrôle + cible, tous points de vue) ;
// « global » = le contrôle partout, qui sort alors des passages (réversible dans
// Réglages > Exclusions).
func (s *Server) accept(w http.ResponseWriter, r *http.Request) {
	to := safeBack(r.PostFormValue("back"))
	note := strings.TrimSpace(r.PostFormValue("note"))
	if note == "" || len(note) > 500 {
		s.back(w, r, to, "err", "Une raison (500 caractères au plus) est nécessaire pour assumer un écart.")
		return
	}
	switch r.PostFormValue("scope") {
	case "global":
		chk := r.PostFormValue("check")
		if chk == "" || len(chk) > 200 || strings.ContainsAny(chk, " \t\r\n") {
			s.back(w, r, to, "err", "Contrôle invalide.")
			return
		}
		rt := s.Settings.Get()
		if !slices.Contains(rt.Exclusions, chk) {
			rt.Exclusions = append(rt.Exclusions, chk)
		}
		if err := s.Settings.Set(r.Context(), rt); err != nil {
			s.back(w, r, to, "err", err.Error())
			return
		}
		if err := s.Store.Accept(r.Context(), "check:"+chk, note, user(r), time.Now()); err != nil {
			s.fail(w, err)
			return
		}
		s.back(w, r, to, "ok", "Contrôle assumé partout : il ne sera plus enregistré. Réactivable dans Réglages.")
	default:
		key := r.PostFormValue("key")
		if len(key) != 32 {
			s.back(w, r, to, "err", "Écart invalide.")
			return
		}
		if err := s.Store.Accept(r.Context(), key, note, user(r), time.Now()); err != nil {
			s.fail(w, err)
			return
		}
		s.back(w, r, to, "ok", "Écart assumé pour cet hôte.")
	}
}

func (s *Server) unaccept(w http.ResponseWriter, r *http.Request) {
	to := safeBack(r.PostFormValue("back"))
	if chk := r.PostFormValue("check"); chk != "" {
		rt := s.Settings.Get()
		rt.Exclusions = slices.DeleteFunc(rt.Exclusions, func(x string) bool { return x == chk })
		if err := s.Settings.Set(r.Context(), rt); err != nil {
			s.back(w, r, to, "err", err.Error())
			return
		}
		s.Store.Unaccept(r.Context(), "check:"+chk)
		s.back(w, r, to, "ok", "Contrôle réactivé : il revient au prochain passage.")
		return
	}
	if err := s.Store.Unaccept(r.Context(), r.PostFormValue("key")); err != nil {
		s.fail(w, err)
		return
	}
	s.back(w, r, to, "ok", "L'écart n'est plus assumé.")
}

func (s *Server) addTarget(w http.ResponseWriter, r *http.Request) {
	var ports []int
	for _, f := range strings.FieldsFunc(r.PostFormValue("ports"), func(c rune) bool { return c == ',' || c == ' ' }) {
		p, err := strconv.Atoi(f)
		if err != nil {
			s.back(w, r, "/inventory", "err", "Port invalide : "+f)
			return
		}
		ports = append(ports, p)
	}
	note := r.PostFormValue("note")
	if len(note) > 200 {
		s.back(w, r, "/inventory", "err", "Note trop longue (200 caractères au plus).")
		return
	}
	if _, err := s.Manual.Add(r.Context(), r.PostFormValue("host"), ports, note); err != nil {
		msg := err.Error()
		if strings.Contains(msg, "UNIQUE") {
			msg = "Cette cible existe déjà."
		}
		s.back(w, r, "/inventory", "err", msg)
		return
	}
	s.back(w, r, "/inventory", "ok", "Cible ajoutée.")
}

func (s *Server) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.Store.DeleteTarget(r.Context(), id); err != nil {
		s.fail(w, err)
		return
	}
	s.back(w, r, "/inventory", "ok", "Cible retirée.")
}

// --- analyse IA ---

func (s *Server) analyze(w http.ResponseWriter, r *http.Request) {
	id := s.runID(r.Context(), r.PathValue("ref"))
	if id == 0 {
		http.NotFound(w, r)
		return
	}
	to := safeBack(r.PostFormValue("back"))
	run, err := s.Store.GetRun(r.Context(), id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	prov, why := s.aiProvider()
	if prov == nil {
		if why == "" {
			why = "Aucun fournisseur d'IA configuré (Réglages > IA)."
		}
		s.back(w, r, to, "err", why)
		return
	}
	if run.Status != "ok" && run.Status != "partial" {
		s.back(w, r, to, "err", "Le passage doit être terminé pour être analysé.")
		return
	}
	s.amu.Lock()
	if msg, busy := s.analyzing[run.ID]; busy && msg == "" {
		s.amu.Unlock()
		s.back(w, r, to, "err", "Analyse déjà en cours.")
		return
	}
	s.analyzing[run.ID] = ""
	s.amu.Unlock()

	ds, err := s.Store.Compare(r.Context(), run.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	var routes []source.Route
	if inv, err := s.Store.Inventory(r.Context(), run.ID); err == nil && len(inv) > 0 {
		json.Unmarshal(inv, &routes)
	}
	mask := r.PostFormValue("mask") == "1"
	first := true
	if runs, err := s.Store.Runs(r.Context(), 200); err == nil {
		for _, x := range runs {
			if x.ID < run.ID && (x.Status == "ok" || x.Status == "partial") {
				first = false
			}
		}
	}
	rt := s.Settings.Get()
	excluded := map[string]string{}
	for _, c := range rt.Exclusions {
		excluded[c] = ""
		if a, err := s.Store.GetAcceptance(r.Context(), "check:"+c); err == nil && a != nil {
			excluded[c] = a.Note
		}
	}
	prompt, unmask := ai.Build(ai.Input{Run: run, First: first, Decided: rt.AI.Context, Excluded: excluded, Deltas: ds, Routes: routes, Mask: mask})
	s.awg.Add(1)
	go func() {
		defer s.awg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		text, err := prov.Analyze(ctx, ai.System, prompt)
		s.amu.Lock()
		defer s.amu.Unlock()
		if err != nil {
			log.Printf("analyse du passage %d : %v", run.ID, err)
			s.analyzing[run.ID] = "Échec de l'analyse : " + err.Error()
			return
		}
		a := store.Analysis{At: time.Now(), Provider: prov.Name(), Masked: mask, Text: unmask(text)}
		if err := s.Store.SaveAnalysis(ctx, run.ID, a); err != nil {
			s.analyzing[run.ID] = "Analyse reçue mais non enregistrée : " + err.Error()
			return
		}
		delete(s.analyzing, run.ID)
	}()
	s.back(w, r, to, "ok", "Analyse lancée : une à deux minutes en général.")
}

// analysisState : analyse enregistrée, en cours, ou échec, pour l'affichage.
func (s *Server) analysisState(ctx context.Context, run int64) (a *store.Analysis, busy bool, msg string) {
	if x, err := s.Store.GetAnalysis(ctx, run); err == nil {
		a = &x
	}
	s.amu.Lock()
	m, ok := s.analyzing[run]
	s.amu.Unlock()
	return a, ok && m == "", m
}
