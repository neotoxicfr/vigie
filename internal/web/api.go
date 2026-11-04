package web

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/store"
)

// healthz : sonde de vie publique, sans aucune donnée.
func healthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, "ok\n")
}

type summaryRun struct {
	Started   string `json:"started"`
	Finished  string `json:"finished,omitempty"`
	Status    string `json:"status"`
	DurationS int64  `json:"duration_s,omitempty"`
}

type summaryOut struct {
	Version string      `json:"version"`
	Running bool        `json:"running"`
	LastRun *summaryRun `json:"last_run"`
	Open    struct {
		Total  int `json:"total"`
		High   int `json:"high"`
		Medium int `json:"medium"`
		Low    int `json:"low"`
	} `json:"open"`
	New      int `json:"new"`
	Accepted int `json:"accepted"`
	Hosts    struct {
		Total  int            `json:"total"`
		Grades map[string]int `json:"grades"`
	} `json:"hosts"`
}

// summary : compteurs du dernier passage pour un tableau de bord, en lecture
// seule, derrière un jeton porteur dédié relu à chaque requête. Aucun nom
// d'hôte ni adresse : seulement des nombres, l'état et des dates.
func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	want := settings.Secret(s.Settings.Get().API.TokenFile)
	if len(want) < 32 {
		http.NotFound(w, r)
		return
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vigie"`)
		http.Error(w, "jeton requis", http.StatusUnauthorized)
		return
	}
	ctx := r.Context()
	run, rows, err := s.state(ctx, 0)
	if err != nil {
		log.Printf("api/summary : %v", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	out := summaryOut{Version: s.Version}
	_, out.Running = s.Runner.Current()
	if run != nil {
		lr := &summaryRun{Started: run.Started.Local().Format(time.RFC3339), Status: run.Status}
		if !run.Finished.IsZero() {
			lr.Finished = run.Finished.Local().Format(time.RFC3339)
			lr.DurationS = int64(run.Finished.Sub(run.Started).Seconds())
		}
		out.LastRun = lr
	}
	for _, x := range rows {
		switch {
		case x.Severity == 0:
		case inTab(x, "assumé"):
			out.Accepted++
		case inTab(x, ""):
			out.Open.Total++
			switch x.Severity {
			case 3:
				out.Open.High++
			case 2:
				out.Open.Medium++
			case 1:
				out.Open.Low++
			}
			if x.State == store.New {
				out.New++
			}
		}
	}
	out.Hosts.Grades = map[string]int{"A": 0, "B": 0, "C": 0, "D": 0, "E": 0, "F": 0}
	for _, h := range s.hostRows(ctx, rows) {
		out.Hosts.Total++
		out.Hosts.Grades[h.Grade]++
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(out)
}
