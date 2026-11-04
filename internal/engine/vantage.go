package engine

import (
	"context"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/neotoxicfr/vigie/internal/scan"
)

// publicView résout comme un visiteur : DNS du système, sauf DNS divisé (le
// système répond une adresse locale, un résolveur public une adresse publique),
// auquel cas la réponse publique fait foi.
type publicView struct {
	resolver string // ip:port ; vide = pas de bascule possible
	isLocal  func(netip.Addr) bool

	mu    sync.Mutex
	cache map[string][]netip.Addr
	split map[string][]netip.Addr // hôte → adresses locales données par le système
}

func newPublicView(resolver string, isLocal func(netip.Addr) bool) *publicView {
	return &publicView{resolver: resolver, isLocal: isLocal, cache: map[string][]netip.Addr{}, split: map[string][]netip.Addr{}}
}

func (p *publicView) vantage() scan.Vantage { return scan.Vantage{Name: "public", Addrs: p.addrs} }

func (p *publicView) addrs(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	p.mu.Lock()
	if c, ok := p.cache[host]; ok {
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()

	sys, sysErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	for i := range sys {
		sys[i] = sys[i].Unmap()
	}
	out := sys
	anyLocal := false
	for _, a := range sys {
		anyLocal = anyLocal || p.isLocal(a)
	}
	if p.resolver != "" && (anyLocal || sysErr != nil) {
		pub := lookupPublic(ctx, p.resolver, host)
		public := false
		for _, a := range pub {
			public = public || !p.isLocal(a)
		}
		if public {
			out = pub
			if anyLocal {
				p.mu.Lock()
				p.split[host] = sys
				p.mu.Unlock()
			}
		}
	}
	if len(out) == 0 && sysErr != nil {
		return nil, sysErr
	}
	p.mu.Lock()
	p.cache[host] = out
	p.mu.Unlock()
	return out, nil
}

// splitHosts : hôtes où la bascule a eu lieu, avec les adresses locales évitées.
func (p *publicView) splitHosts() map[string][]netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string][]netip.Addr, len(p.split))
	for k, v := range p.split {
		out[k] = v
	}
	return out
}

// lookupPublic interroge le résolveur public en A et AAAA (CNAME suivis par lui).
func lookupPublic(ctx context.Context, resolver, host string) []netip.Addr {
	c := &dns.Client{Timeout: 5 * time.Second}
	var out []netip.Addr
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), t)
		r, _, err := c.ExchangeContext(ctx, m, resolver)
		if err != nil || r.Rcode != dns.RcodeSuccess {
			continue
		}
		for _, rr := range r.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(v.A); ok {
					out = append(out, a.Unmap())
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(v.AAAA); ok {
					out = append(out, a)
				}
			}
		}
	}
	return out
}

// sameAddrs : l'origine vise exactement ce que le public voit déjà ; la mesurer
// deux fois afficherait deux fois le même écart.
func sameAddrs(a, b []netip.Addr) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	x := append([]netip.Addr{}, a...)
	y := append([]netip.Addr{}, b...)
	sort.Slice(x, func(i, j int) bool { return x[i].Less(x[j]) })
	sort.Slice(y, func(i, j int) bool { return y[i].Less(y[j]) })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
