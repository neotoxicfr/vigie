// gencdn met à jour les plages publiées des CDN embarquées par netinfo
// (go generate ./internal/netinfo). Lecture seule de sources officielles.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const maxBody = 16 << 20

var client = &http.Client{Timeout: 60 * time.Second}

func get(url string) []byte {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", "vigie-gencdn")
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("%s : statut %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func getJSON(url string, v any) {
	if err := json.Unmarshal(get(url), v); err != nil {
		log.Fatalf("%s : %v", url, err)
	}
}

func cloudflare() []string {
	var out []string
	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		out = append(out, strings.Fields(string(get(u)))...)
	}
	return out
}

func fastly() []string {
	var v struct {
		V4 []string `json:"addresses"`
		V6 []string `json:"ipv6_addresses"`
	}
	getJSON("https://api.fastly.com/public-ip-list", &v)
	return append(v.V4, v.V6...)
}

// cloudfront garde CLOUDFRONT et CLOUDFRONT_ORIGIN_FACING : ce dernier est
// justement ce qu'une origine met en liste blanche.
func cloudfront() []string {
	var v struct {
		V4 []struct {
			Prefix  string `json:"ip_prefix"`
			Service string `json:"service"`
		} `json:"prefixes"`
		V6 []struct {
			Prefix  string `json:"ipv6_prefix"`
			Service string `json:"service"`
		} `json:"ipv6_prefixes"`
	}
	getJSON("https://ip-ranges.amazonaws.com/ip-ranges.json", &v)
	keep := func(s string) bool { return s == "CLOUDFRONT" || s == "CLOUDFRONT_ORIGIN_FACING" }
	var out []string
	for _, p := range v.V4 {
		if keep(p.Service) {
			out = append(out, p.Prefix)
		}
	}
	for _, p := range v.V6 {
		if keep(p.Service) {
			out = append(out, p.Prefix)
		}
	}
	return out
}

func bunny() []string {
	var out []string
	for _, u := range []string{"https://bunnycdn.com/api/system/edgeserverlist", "https://bunnycdn.com/api/system/edgeserverlist/IPv6"} {
		var v []string
		getJSON(u, &v)
		out = append(out, v...)
	}
	return out
}

// google : pas de liste propre au CDN ; les plages des proxys (GFE) sont
// documentées sans liste téléchargeable, celles des NEG Internet sont publiées
// en TXT.
func google() []string {
	out := []string{"35.191.0.0/16", "130.211.0.0/22"}
	txts, err := net.LookupTXT("_cloud-eoips.googleusercontent.com")
	if err != nil {
		log.Fatal(err)
	}
	for _, t := range txts {
		for _, f := range strings.Fields(t) {
			if p, ok := strings.CutPrefix(f, "ip4:"); ok {
				out = append(out, p)
			} else if p, ok := strings.CutPrefix(f, "ip6:"); ok {
				out = append(out, p)
			}
		}
	}
	return out
}

func write(dir, name, src string, raw []string) {
	set := map[netip.Prefix]bool{}
	for _, s := range raw {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, err2 := netip.ParseAddr(s)
			if err2 != nil {
				log.Fatalf("%s : %q invalide", name, s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		set[p.Masked()] = true
	}
	if len(set) == 0 {
		log.Fatalf("%s : liste vide", name)
	}
	ps := make([]netip.Prefix, 0, len(set))
	for p := range set {
		ps = append(ps, p)
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n# source : %s\n# mis à jour : %s\n", name, src, time.Now().UTC().Format("2006-01-02"))
	for _, p := range ps {
		b.WriteString(p.String() + "\n")
	}
	if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(b.String()), 0o644); err != nil {
		log.Fatal(err)
	}
}

func main() {
	dir := "cdn"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	write(dir, "cloudflare", "https://www.cloudflare.com/ips-v4 , ips-v6", cloudflare())
	write(dir, "fastly", "https://api.fastly.com/public-ip-list", fastly())
	write(dir, "cloudfront", "https://ip-ranges.amazonaws.com/ip-ranges.json (CLOUDFRONT, CLOUDFRONT_ORIGIN_FACING)", cloudfront())
	write(dir, "bunny", "https://bunnycdn.com/api/system/edgeserverlist , /IPv6", bunny())
	write(dir, "google", "GFE documentés (35.191.0.0/16, 130.211.0.0/22) + TXT _cloud-eoips.googleusercontent.com", google())
}
