// Package cdnprov lit la configuration d'un CDN par son API : ce que le CDN
// impose devant les hôtes (TLS, règles de pare-feu, proxy DNS).
package cdnprov

import (
	"context"
	"net/netip"
	"slices"
	"strings"

	"github.com/neotoxicfr/vigie/internal/check"
)

// Result : Notes résume, par hôte, les règles du CDN qu'un inconnu rencontre
// (pour la déduction de la vue « inconnu ») ; Proxied dit si l'hôte passe par
// le CDN d'après la zone.
type Result struct {
	Findings []check.Finding
	Notes    map[string]string
	Proxied  map[string]bool
	// Geo : hôte proxifié → règles géographiques de blocage (lecture des
	// expressions, pas évaluation) ; sert à juger les mesures des sorties.
	Geo map[string]Geo
	// Origins : cibles publiques des enregistrements proxifiés, c'est-à-dire
	// l'origine telle que le CDN la joint.
	Origins []netip.Addr
}

// Provider lit la configuration du CDN pour hosts, dont les adresses de
// l'origine (Result.Origins). Une erreur non nulle peut accompagner un Result
// partiel, exploitable.
type Provider interface {
	Name() string
	Scan(ctx context.Context, hosts []string) (Result, error)
}

// Geo : pays autorisés (tout le reste bloqué) et pays bloqués par les règles.
type Geo struct {
	Allowed []string
	Blocked []string
}

// Blocks dit si un visiteur de ce pays est bloqué par ces règles.
func (g Geo) Blocks(country string) bool {
	c := strings.ToUpper(country)
	if len(g.Allowed) > 0 && !slices.Contains(g.Allowed, c) {
		return true
	}
	return slices.Contains(g.Blocked, c)
}
