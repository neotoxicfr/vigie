// Package scan porte le contrat commun des contrôles actifs : la cible, les
// points de vue mesurés et les garde-fous (concurrence, délai, budget, 429).
package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/neotoxicfr/vigie/internal/source"
)

// UserAgent de toutes les requêtes HTTP de vigie ; Version est posée par main.
var Version = "dev"

func UserAgent() string { return "vigie/" + Version }

// Target est un couple hôte/port à contrôler, avec la route qui l'a fait connaître.
type Target struct {
	Host  string        // nom d'hôte ou IP littérale, sans port
	Port  int           // 443, 80…
	TLS   bool          // la source annonce du TLS sur ce port
	Paths []string      // chemins propres à la route (PathPrefix…), éventuellement vides
	Page  string        // page jugée à la place de « / » (chemin et requête), vide = « / »
	Route *source.Route // nil pour une cible sans route
}

func (t Target) String() string {
	if t.Port == 0 {
		return t.Host
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// Vantage est un point de vue mesuré : il dit à quelles adresses se connecter
// pour joindre un hôte. « dns » résout normalement ; « origine » renvoie les
// adresses d'origine déclarées ; « interne » l'adresse du proxy ou du backend.
type Vantage struct {
	Name  string
	Addrs func(ctx context.Context, host string) ([]netip.Addr, error)
	Proxy *Proxy // non nil : sortie par un proxy (TCP seulement)
}

// DNS est le point de vue par résolution système.
func DNS() Vantage {
	return Vantage{Name: "dns", Addrs: func(ctx context.Context, host string) ([]netip.Addr, error) {
		if a, err := netip.ParseAddr(host); err == nil {
			return []netip.Addr{a}, nil
		}
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}}
}

// Fixed renvoie toujours les mêmes adresses, quel que soit l'hôte (origine, interne).
func Fixed(name string, addrs ...netip.Addr) Vantage {
	return Vantage{Name: name, Addrs: func(context.Context, string) ([]netip.Addr, error) { return addrs, nil }}
}

var (
	ErrBudget    = errors.New("budget de requêtes du passage épuisé")
	ErrSuspended = errors.New("hôte suspendu")
)

// Guard limite la pression sur chaque hôte : au plus PerHost connexions
// simultanées, Delay entre deux départs vers le même hôte, Budget opérations au
// total pour le passage. Un hôte qui répond 429 est suspendu jusqu'à la fin.
type Guard struct {
	perHost int
	delay   time.Duration

	mu        sync.Mutex
	budget    int
	nextAny   map[string]time.Time // prochain départ autorisé par IP de sortie, tous hôtes confondus
	hosts     map[string]*hostState
	suspended map[string]string
}

type hostState struct {
	sem  chan struct{}
	next time.Time
}

const (
	DefaultPerHost = 2
	DefaultDelay   = 250 * time.Millisecond
	DefaultBudget  = 5000
	// GlobalInterval plafonne le débit total (20 départs/s) : les limites de débit
	// des proxys comptent souvent par IP cliente, donc pour vigie tout entier.
	GlobalInterval = 50 * time.Millisecond
)

func NewGuard(budget, perHost int, delay time.Duration) *Guard {
	return &Guard{perHost: perHost, delay: delay, budget: budget,
		hosts: map[string]*hostState{}, suspended: map[string]string{}, nextAny: map[string]time.Time{}}
}

// Acquire réserve une opération vers host ; appeler release une fois la
// connexion ou la requête terminée.
func (g *Guard) Acquire(ctx context.Context, host string) (release func(), err error) {
	return g.AcquireFrom(ctx, "", host)
}

// AcquireFrom : comme Acquire, le plafond global étant compté par IP de sortie
// (src : "" = la machine elle-même, sinon le nom de la sortie par proxy), car les
// limites de débit des proxys et des CDN comptent par IP cliente.
func (g *Guard) AcquireFrom(ctx context.Context, src, host string) (release func(), err error) {
	g.mu.Lock()
	if r, ok := g.suspended[host]; ok {
		g.mu.Unlock()
		return nil, fmt.Errorf("%w : %s", ErrSuspended, r)
	}
	if g.budget <= 0 {
		g.mu.Unlock()
		return nil, ErrBudget
	}
	g.budget--
	h := g.hosts[host]
	if h == nil {
		h = &hostState{sem: make(chan struct{}, g.perHost)}
		g.hosts[host] = h
	}
	g.mu.Unlock()

	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	g.mu.Lock()
	start := time.Now()
	if h.next.After(start) {
		start = h.next
	}
	if na := g.nextAny[src]; na.After(start) {
		start = na
	}
	h.next = start.Add(g.delay)
	g.nextAny[src] = start.Add(GlobalInterval)
	wait := time.Until(start)
	g.mu.Unlock()
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case <-t.C:
		case <-ctx.Done():
			<-h.sem
			return nil, ctx.Err()
		}
	}
	return func() { <-h.sem }, nil
}

func (g *Guard) Suspend(host, reason string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.suspended[host]; !ok {
		g.suspended[host] = reason
	}
}

// Exhausted dit si le budget du passage est épuisé.
func (g *Guard) Exhausted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.budget <= 0
}

// Suspended renvoie une copie des hôtes suspendus et de leur raison.
func (g *Guard) Suspended() map[string]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]string, len(g.suspended))
	for k, v := range g.suspended {
		out[k] = v
	}
	return out
}

// Dial ouvre une connexion TCP vers host:port par le point de vue v, sous le
// contrôle du garde ; la première adresse qui répond gagne. La connexion rend
// sa place au garde à sa fermeture.
func (g *Guard) Dial(ctx context.Context, v Vantage, host string, port int) (net.Conn, error) {
	if v.Proxy != nil {
		release, err := g.AcquireFrom(ctx, v.Name, host)
		if err != nil {
			return nil, err
		}
		c, err := v.Proxy.Dial(ctx, host, port)
		if err != nil {
			release()
			return nil, err
		}
		return &guardedConn{Conn: c, release: release}, nil
	}
	addrs, err := v.Addrs(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("%s : aucune adresse pour %s", v.Name, host)
	}
	release, err := g.Acquire(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 10 * time.Second}
	var errs []error
	for _, a := range addrs {
		c, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(a, uint16(port)).String())
		if err == nil {
			return &guardedConn{Conn: c, release: release}, nil
		}
		errs = append(errs, err)
	}
	release()
	return nil, errors.Join(errs...)
}

type guardedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *guardedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}
