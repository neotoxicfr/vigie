// Package manual fournit les cibles saisies à la main dans l'interface.
package manual

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

type Manual struct{ st *store.Store }

func New(st *store.Store) *Manual { return &Manual{st} }

func (m *Manual) Name() string { return "manuel" }

func (m *Manual) Discover(ctx context.Context) ([]source.Route, error) {
	ts, err := m.st.Targets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]source.Route, 0, len(ts))
	for _, t := range ts {
		out = append(out, source.Route{Source: m.Name(), Name: t.Host, Hosts: []string{t.Host}, Ports: t.Ports})
	}
	return out, nil
}

// Add valide puis enregistre une cible : c'est l'entrée depuis l'interface.
func (m *Manual) Add(ctx context.Context, host string, ports []int, note string) (int64, error) {
	h, ps, err := Validate(host, ports)
	if err != nil {
		return 0, err
	}
	return m.st.AddTarget(ctx, store.Target{Host: h, Ports: ps, Note: strings.TrimSpace(note), Added: time.Now()})
}

// Validate normalise un nom d'hôte (RFC 1123, sans joker) ou une IP, et des
// ports 1-65535 triés sans doublon.
func Validate(host string, ports []int) (string, []int, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
		if a.Zone() != "" {
			return "", nil, errors.New("adresse avec zone refusée")
		}
		h = a.String()
	} else if err := validHostname(h); err != nil {
		return "", nil, err
	}
	ps := slices.Clone(ports)
	slices.Sort(ps)
	ps = slices.Compact(ps)
	for _, p := range ps {
		if p < 1 || p > 65535 {
			return "", nil, fmt.Errorf("port %d hors de 1-65535", p)
		}
	}
	return h, ps, nil
}

func validHostname(h string) error {
	if h == "" || len(h) > 253 {
		return errors.New("nom d'hôte vide ou trop long")
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return fmt.Errorf("nom d'hôte invalide : %q", h)
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return fmt.Errorf("nom d'hôte invalide : %q", h)
			}
		}
	}
	return nil
}
