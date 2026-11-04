// Package authprov décrit un fournisseur d'authentification dont on lit les
// règles d'accès, pour déduire ce qu'un visiteur anonyme obtient.
package authprov

import "net/netip"

// Politiques possibles d'une Decision.
const (
	Bypass    = "bypass"
	OneFactor = "one_factor"
	TwoFactor = "two_factor"
	Deny      = "deny"
)

// Decision est la politique appliquée à une requête anonyme : Rule est
// l'index (base 0) de la règle retenue, -1 pour la politique par défaut.
type Decision struct {
	Policy string
	Rule   int
	Reason string
}

// Provider décide pour un visiteur anonyme (aucune identité connue).
type Provider interface {
	Name() string
	Decide(host, path, method string, ip netip.Addr) Decision
}

// Networker est implémenté par un fournisseur qui sait lister les réseaux
// cités dans ses règles (pour choisir une IP « inconnue » hors de ceux-ci).
type Networker interface {
	Networks() []netip.Prefix
}
