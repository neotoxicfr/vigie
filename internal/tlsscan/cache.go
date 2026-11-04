package tlsscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

// Cache partage l'énumération des protocoles, suites et groupes entre les hôtes
// servis par la même adresse avec la même configuration TLS : derrière un CDN ou
// un reverse proxy, elle est presque toujours commune. Une empreinte de trois
// poignées de main (négociation libre, plafond TLS 1.2, plafond TLS 1.1) décide
// de la reprise : des options TLS propres à une route donnent une autre empreinte,
// donc une énumération complète. Un passage = un Cache.
type Cache struct {
	mu sync.Mutex
	m  map[string]*cached
}

type cached struct {
	ready    chan struct{}
	findings []check.Finding // énumération seule, cibles à réécrire
	ok       bool
}

func NewCache() *Cache { return &Cache{m: map[string]*cached{}} }

// ScanCached fait comme Scan, en reprenant l'énumération d'un hôte de même
// empreinte déjà mesuré par ce point de vue.
func ScanCached(ctx context.Context, g *scan.Guard, v scan.Vantage, host string, port int, c *Cache) []check.Finding {
	if c == nil {
		return Scan(ctx, g, v, host, port)
	}
	p := &prober{g: g, v: v, host: host, port: port}
	free, freeAddr, err := p.stdAddr(ctx, &tls.Config{ServerName: p.sni(), MinVersion: tls.VersionTLS10})
	if err != nil {
		return Scan(ctx, g, v, host, port)
	}
	sig := fmt.Sprintf("%s|%s|%d|%x|%x", v.Name, freeAddr, port, free.Version, free.CipherSuite)
	for _, max := range []uint16{tls.VersionTLS12, tls.VersionTLS11} {
		st, _, err := p.stdAddr(ctx, &tls.Config{ServerName: p.sni(), MinVersion: tls.VersionTLS10, MaxVersion: max})
		if err != nil {
			sig += "|-"
		} else {
			sig += fmt.Sprintf("|%x/%x", st.Version, st.CipherSuite)
		}
	}

	c.mu.Lock()
	e, seen := c.m[sig]
	if !seen {
		e = &cached{ready: make(chan struct{})}
		c.m[sig] = e
	}
	c.mu.Unlock()

	if seen {
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil
		}
		if e.ok {
			target := net.JoinHostPort(host, strconv.Itoa(port))
			out := scanCertOnly(ctx, g, v, host, port)
			for _, f := range e.findings {
				f.Target = target
				out = append(out, f)
			}
			return out
		}
		return Scan(ctx, g, v, host, port)
	}

	all := Scan(ctx, g, v, host, port)
	var enum []check.Finding
	for _, f := range all {
		if isEnum(f.Check) {
			enum = append(enum, f)
		}
	}
	e.findings, e.ok = enum, len(enum) > 0
	close(e.ready)
	return all
}

// isEnum : constats qui dépendent de la configuration TLS du serveur, pas de
// l'hôte (le certificat, lui, dépend du nom).
func isEnum(id string) bool {
	for _, p := range []string{"tls.protocol.", "tls.cipher.", "tls.groups"} {
		if len(id) >= len(p) && id[:len(p)] == p {
			return true
		}
	}
	return false
}

// stdAddr : poignée de main crypto/tls, avec l'adresse effectivement jointe.
func (p *prober) stdAddr(ctx context.Context, cfg *tls.Config) (tls.ConnectionState, string, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return tls.ConnectionState{}, "", err
	}
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	_ = conn.SetDeadline(deadline(ctx))
	cfg.InsecureSkipVerify = true
	tc := tls.Client(conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, addr, err
	}
	return tc.ConnectionState(), addr, nil
}
