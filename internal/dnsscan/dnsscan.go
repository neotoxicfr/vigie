// Package dnsscan contrôle la configuration DNS des hôtes (résolution, exposition
// de l'origine, CDN, IPv6) et des zones (DNSSEC validé, CAA, courrier).
package dnsscan

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

type Options struct {
	Resolver string                // ip:port ; vide = premier serveur de /etc/resolv.conf
	Origins  []netip.Addr          // adresses d'origine : un hôte qui y résout est exposé
	IsCDN    func(netip.Addr) bool // nil = pas de contrôle CDN
}

type scanner struct {
	ctx      context.Context
	g        *scan.Guard
	resolver string
	resErr   error
	cache    map[string]*qres
	zones    map[string]*zstate
	cuts     map[string]cutRes
	out      []check.Finding
}

type qres struct {
	m   *dns.Msg
	err error
}

func (s *scanner) add(id, target string, sev check.Severity, title, evidence string) {
	if len(evidence) > 300 {
		evidence = evidence[:299] + "…"
	}
	s.out = append(s.out, check.Finding{Check: id, Target: target, Vantage: "dns", Severity: sev, Title: title, Evidence: evidence})
}

// Scan contrôle chaque hôte puis, une fois par zone (domaine enregistrable), la zone.
func Scan(ctx context.Context, g *scan.Guard, o Options, hosts []string) []check.Finding {
	s := &scanner{ctx: ctx, g: g, cache: map[string]*qres{}, zones: map[string]*zstate{}, cuts: map[string]cutRes{}}
	s.resolver, s.resErr = resolverAddr(o.Resolver)

	var names []string
	seen := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
		if h == "" || seen[h] {
			continue
		}
		if _, err := netip.ParseAddr(h); err == nil {
			continue
		}
		seen[h] = true
		names = append(names, h)
	}
	sort.Strings(names)

	type hostInfo struct {
		host  string
		addrs []netip.Addr
	}
	byZone := map[string][]hostInfo{}
	var zoneOrder []string
	zoneSeen := map[string]bool{}
	for _, h := range names {
		if ctx.Err() != nil {
			break
		}
		addrs, ok := s.checkHost(h, o)
		z, err := publicsuffix.EffectiveTLDPlusOne(h)
		if err != nil {
			continue
		}
		if !zoneSeen[z] {
			zoneSeen[z] = true
			zoneOrder = append(zoneOrder, z)
		}
		if ok {
			byZone[z] = append(byZone[z], hostInfo{h, addrs})
		}
	}

	for _, z := range zoneOrder {
		if ctx.Err() != nil {
			break
		}
		if o.IsCDN != nil {
			var behind, bare []string
			for _, hi := range byZone[z] {
				cdn := false
				for _, a := range hi.addrs {
					cdn = cdn || o.IsCDN(a)
				}
				if cdn {
					behind = append(behind, hi.host)
				} else {
					bare = append(bare, hi.host)
				}
			}
			if len(behind) > 0 {
				for _, h := range bare {
					s.add("dns.no-cdn", h, check.Info, "Hôte hors CDN alors que d'autres hôtes de la zone y sont",
						"autres hôtes derrière un CDN : "+strings.Join(behind, ", "))
				}
			}
		}
		s.checkZone(z)
	}
	return s.out
}

func resolverAddr(r string) (string, error) {
	if r == "" {
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cc.Servers) == 0 {
			return "", fmt.Errorf("aucun résolveur configuré")
		}
		return net.JoinHostPort(cc.Servers[0], cc.Port), nil
	}
	if _, _, err := net.SplitHostPort(r); err != nil {
		return net.JoinHostPort(strings.Trim(r, "[]"), "53"), nil
	}
	return r, nil
}

// q interroge le résolveur (UDP, repli TCP si tronqué) avec EDNS0 et DO. Pour la
// validation DNSSEC (dnssec=true), CD est posé : on veut les données même si le
// résolveur les juge invalides, c'est nous qui les validons.
func (s *scanner) q(name string, qtype uint16, dnssec bool) (*dns.Msg, error) {
	name = strings.ToLower(dns.Fqdn(name))
	key := fmt.Sprintf("%s|%d|%t", name, qtype, dnssec)
	if r, ok := s.cache[key]; ok {
		return r.m, r.err
	}
	m, err := s.exchange(name, qtype, dnssec)
	s.cache[key] = &qres{m, err}
	return m, err
}

func (s *scanner) exchange(name string, qtype uint16, cd bool) (*dns.Msg, error) {
	if s.resErr != nil {
		return nil, s.resErr
	}
	req := new(dns.Msg)
	req.SetQuestion(name, qtype)
	req.RecursionDesired = true
	req.CheckingDisabled = cd
	req.SetEdns0(1232, true)
	var r *dns.Msg
	var err error
	for i := 0; i < 2 && s.ctx.Err() == nil; i++ { // un réessai UDP
		if r, err = s.once("udp", req); err == nil {
			break
		}
	}
	if err == nil && r.Truncated {
		r, err = s.once("tcp", req)
	}
	return r, err
}

func (s *scanner) once(network string, req *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 6*time.Second)
	defer cancel()
	c := &dns.Client{Net: network, Timeout: 5 * time.Second}
	r, _, err := c.ExchangeContext(ctx, req, s.resolver)
	return r, err
}

func pick[T dns.RR](m *dns.Msg, owner string) []T {
	var out []T
	if m == nil {
		return nil
	}
	for _, rr := range m.Answer {
		if t, ok := rr.(T); ok && strings.EqualFold(rr.Header().Name, owner) {
			out = append(out, t)
		}
	}
	return out
}

func (s *scanner) checkHost(h string, o Options) ([]netip.Addr, bool) {
	a, errA := s.q(h, dns.TypeA, false)
	aaaa, errAAAA := s.q(h, dns.TypeAAAA, false)
	var addrs []netip.Addr
	var cnames []string
	collect := func(m *dns.Msg) {
		if m == nil {
			return
		}
		for _, rr := range m.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if ip, ok := netip.AddrFromSlice(v.A); ok {
					addrs = append(addrs, ip.Unmap())
				}
			case *dns.AAAA:
				if ip, ok := netip.AddrFromSlice(v.AAAA); ok {
					addrs = append(addrs, ip)
				}
			case *dns.CNAME:
				cnames = append(cnames, v.Target)
			}
		}
	}
	collect(a)
	collect(aaaa)
	cname := ""
	if len(cnames) > 0 {
		cname = " ; CNAME → " + strings.TrimSuffix(cnames[len(cnames)-1], ".")
	}
	if len(addrs) == 0 {
		why := "aucune adresse A ou AAAA"
		switch {
		case errA != nil:
			why = errA.Error()
		case a.Rcode != dns.RcodeSuccess:
			why = dns.RcodeToString[a.Rcode]
		case errAAAA != nil:
			why = errAAAA.Error()
		}
		s.add("dns.resolve.fail", h, check.Medium, "L'hôte ne se résout pas", why+cname)
		return nil, false
	}
	var exposed []string
	for _, ad := range addrs {
		for _, org := range o.Origins {
			if ad == org {
				exposed = append(exposed, ad.String())
			}
		}
	}
	if len(exposed) > 0 {
		s.add("dns.origin-exposed", h, check.Medium, "Le DNS public révèle l'adresse d'origine", strings.Join(exposed, ", ")+cname)
	}
	if aaaa != nil && aaaa.Rcode == dns.RcodeSuccess && !hasType(aaaa, dns.TypeAAAA) {
		s.add("dns.ipv6.absent", h, check.Info, "Aucun enregistrement AAAA", "IPv4 seul"+cname)
	}
	return addrs, true
}

func hasType(m *dns.Msg, t uint16) bool {
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == t {
			return true
		}
	}
	return false
}
