// Package check définit le résultat commun à tous les contrôles.
package check

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case Low:
		return "faible"
	case Medium:
		return "moyen"
	case High:
		return "élevé"
	}
	return "info"
}

// Finding est un constat d'un contrôle, sur une cible, depuis un point de vue.
type Finding struct {
	Check      string   `json:"check"`   // identifiant stable du contrôle, ex. "http.hsts"
	Target     string   `json:"target"`  // hôte[:port][/chemin]
	Vantage    string   `json:"vantage"` // dns, origine, interne, inconnu
	Privileged bool     `json:"privileged"`
	Severity   Severity `json:"severity"`
	Title      string   `json:"title"`
	Evidence   string   `json:"evidence"`
}

// Key identifie le constat d'un passage à l'autre. Elle ignore la preuve, qui
// peut varier (date, nonce) sans que le constat change.
func (f Finding) Key() string {
	h := sha256.Sum256([]byte(f.Check + "\x00" + f.Target + "\x00" + f.Vantage))
	return hex.EncodeToString(h[:16])
}

// IssueKey identifie l'écart quel que soit le point de vue : c'est la clé de
// regroupement à l'affichage et celle des écarts assumés pour un hôte.
func (f Finding) IssueKey() string {
	h := sha256.Sum256([]byte(f.Check + "\x00" + f.Target))
	return hex.EncodeToString(h[:16])
}

// Unit est l'unité mesurée d'une cible : l'hôte sans port ni chemin. Un passage
// partiel ne conclut rien sur une unité qu'il n'a pas mesurée.
func Unit(target string) string {
	t := target
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(t)
}
