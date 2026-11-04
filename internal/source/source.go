// Package source définit le modèle commun des routes découvertes, quelle que
// soit la source (reverse proxy ou saisie manuelle).
package source

import (
	"context"
	"encoding/json"
	"net/netip"
)

type Source interface {
	Name() string
	Discover(ctx context.Context) ([]Route, error)
}

// Route est un service publié : ses hôtes, ports, la chaîne de middlewares
// effectivement appliquée (chaînes déroulées) et ses backends.
type Route struct {
	Source      string       `json:"source"` // ex. "traefik/nas"
	Name        string       `json:"name"`
	Rule        string       `json:"rule,omitempty"`
	Hosts       []string     `json:"hosts"`
	Paths       []string     `json:"paths,omitempty"`
	Ports       []int        `json:"ports,omitempty"`
	TLS         bool         `json:"tls"`
	Declared    []string     `json:"declared,omitempty"` // middlewares tels que déclarés, chaînes non déroulées
	Middlewares []Middleware `json:"middlewares,omitempty"`
	Backends    []string     `json:"backends,omitempty"`
	Problems    []string     `json:"problems,omitempty"` // références cassées, cycles…
}

// Kind classe un middleware indépendamment du proxy qui le porte.
type Kind string

const (
	IPAllow     Kind = "ip-allow"
	ForwardAuth Kind = "forward-auth"
	BasicAuth   Kind = "basic-auth"
	Headers     Kind = "headers"
	RateLimit   Kind = "rate-limit"
	Redirect    Kind = "redirect"
	Other       Kind = "other"
)

type Middleware struct {
	Name      string         `json:"name"`
	Type      string         `json:"type"` // type propre à la source
	Kind      Kind           `json:"kind"`
	AllowFrom []netip.Prefix `json:"allow_from,omitempty"` // IPAllow
	// OrAuth (IPAllow) : une authentification de la chaîne suffit aussi
	// (nginx « satisfy any ») ; un inconnu refusé par la liste passe par elle.
	OrAuth  bool            `json:"or_auth,omitempty"`
	AuthURL string          `json:"auth_url,omitempty"` // ForwardAuth
	Config  json.RawMessage `json:"config,omitempty"`   // config brute, pour les contrôles propres à la source
}
