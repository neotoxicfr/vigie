// Package settings garde les réglages modifiables dans l'interface (config.Runtime)
// en base ; le fichier de configuration ne sert qu'à les initialiser.
package settings

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/neotoxicfr/vigie/internal/config"
)

const key = "runtime"

type kv interface {
	Setting(ctx context.Context, key, def string) (string, error)
	SetSetting(ctx context.Context, key, value string) error
}

// Load rend les réglages en base ; au premier démarrage, seed (le fichier) les initialise.
func Load(ctx context.Context, st kv, seed config.Runtime) (config.Runtime, error) {
	raw, err := st.Setting(ctx, key, "")
	if err != nil {
		return seed, err
	}
	if raw == "" {
		return seed, Save(ctx, st, seed)
	}
	r := config.DefaultRuntime()
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		return seed, fmt.Errorf("réglages en base illisibles : %w", err)
	}
	return r, nil
}

// Save valide puis enregistre : un réglage invalide n'atteint jamais la base.
func Save(ctx context.Context, st kv, r config.Runtime) error {
	if err := r.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, key, string(b))
}

// Live : les réglages en mémoire, relus par chaque passage et chaque requête ;
// Set les valide, les enregistre, puis les applique sans redémarrage.
type Live struct {
	st kv
	mu sync.RWMutex
	r  config.Runtime
}

func NewLive(ctx context.Context, st kv, seed config.Runtime) (*Live, error) {
	r, err := Load(ctx, st, seed)
	if err != nil {
		return nil, err
	}
	return &Live{st: st, r: r}, nil
}

func (l *Live) Get() config.Runtime {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return clone(l.r)
}

func (l *Live) Set(ctx context.Context, r config.Runtime) error {
	if err := Save(ctx, l.st, r); err != nil {
		return err
	}
	l.mu.Lock()
	l.r = clone(r)
	l.mu.Unlock()
	return nil
}

// clone : copie profonde par JSON, pour qu'aucun appelant ne modifie l'état partagé.
func clone(r config.Runtime) config.Runtime {
	b, _ := json.Marshal(r)
	var out config.Runtime
	json.Unmarshal(b, &out)
	return out
}

// Secret lit un fichier secret ; "" s'il est absent ou vide.
func Secret(path string) string {
	if path == "" {
		return ""
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
