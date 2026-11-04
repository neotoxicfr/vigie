// Package sched lance les passages planifiés selon la cadence réglée dans l'interface.
package sched

import (
	"context"
	"log"
	"time"

	"github.com/neotoxicfr/vigie/internal/store"
)

type Starter interface {
	Start() (int64, error)
	Current() (int64, bool)
}

// Due dit si un passage est dû : cadence active et dernier départ assez ancien.
func Due(last time.Time, cadence time.Duration, now time.Time) bool {
	return cadence > 0 && (last.IsZero() || !now.Before(last.Add(cadence)))
}

// Loop vérifie chaque minute jusqu'à l'annulation de ctx.
func Loop(ctx context.Context, st *store.Store, r Starter) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		v, err := st.Setting(ctx, "cadence", "0")
		if err != nil {
			log.Printf("planification : %v", err)
			continue
		}
		cadence, err := time.ParseDuration(v)
		if err != nil || cadence <= 0 {
			continue
		}
		if _, running := r.Current(); running {
			continue
		}
		var last time.Time
		if runs, err := st.Runs(ctx, 1); err == nil && len(runs) > 0 {
			last = runs[0].Started
		}
		if Due(last, cadence, time.Now()) {
			if id, err := r.Start(); err != nil {
				log.Printf("planification : %v", err)
			} else {
				log.Printf("planification : passage %d lancé", id)
			}
		}
	}
}
