// Package netinfo classe les adresses : locales, privées, ou appartenant à un
// CDN d'après les plages publiées (embarquées, mises à jour par gencdn).
package netinfo

//go:generate go run ./gencdn cdn

import (
	"bufio"
	"embed"
	"net"
	"net/netip"
	"path"
	"slices"
	"strings"
	"sync"
)

// LocalPrefixes donne les préfixes des interfaces de la machine.
func LocalPrefixes() ([]netip.Prefix, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, _ := n.Mask.Size()
		ip = ip.Unmap()
		if ip.Is4() && ones > 32 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(ip, ones).Masked())
	}
	return out, nil
}

// LocalAddrs rend les adresses des interfaces telles quelles (pas l'adresse
// réseau) : ce sont les IP sources possibles de vigie.
func LocalAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, ip.Unmap())
			}
		}
	}
	return out
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsLocal : bouclage, privé (RFC 1918, ULA), lien-local, CGNAT, ou dans local.
func IsLocal(a netip.Addr, local []netip.Prefix) bool {
	a = a.Unmap()
	if !a.IsValid() {
		return false
	}
	if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a) {
		return true
	}
	for _, p := range local {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

//go:embed cdn/*.txt
var cdnFS embed.FS

var (
	cdnOnce sync.Once
	cdnList map[string][]netip.Prefix
	cdnName []string // ordre stable pour CDN
)

func loadCDN() {
	cdnList = map[string][]netip.Prefix{}
	files, _ := cdnFS.ReadDir("cdn")
	for _, f := range files {
		name := strings.TrimSuffix(f.Name(), ".txt")
		data, _ := cdnFS.ReadFile(path.Join("cdn", f.Name()))
		sc := bufio.NewScanner(strings.NewReader(string(data)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if p, err := netip.ParsePrefix(line); err == nil {
				cdnList[name] = append(cdnList[name], p)
			}
		}
		cdnName = append(cdnName, name)
	}
	slices.Sort(cdnName)
}

// CDN dit à quel fournisseur appartient a, d'après les plages embarquées.
func CDN(a netip.Addr) (provider string, ok bool) {
	cdnOnce.Do(loadCDN)
	a = a.Unmap()
	for _, name := range cdnName {
		for _, p := range cdnList[name] {
			if p.Contains(a) {
				return name, true
			}
		}
	}
	return "", false
}

// CDNPrefixes donne une copie des plages d'un fournisseur (cloudflare, fastly,
// cloudfront, google, bunny) ; nil s'il est inconnu.
func CDNPrefixes(provider string) []netip.Prefix {
	cdnOnce.Do(loadCDN)
	return slices.Clone(cdnList[provider])
}

// CDNOverlap donne le fournisseur dont une plage chevauche p, s'il y en a un.
func CDNOverlap(p netip.Prefix) (provider string, ok bool) {
	cdnOnce.Do(loadCDN)
	for _, name := range cdnName {
		for _, q := range cdnList[name] {
			if q.Overlaps(p) {
				return name, true
			}
		}
	}
	return "", false
}
