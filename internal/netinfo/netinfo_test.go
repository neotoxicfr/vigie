package netinfo

import (
	"net/netip"
	"testing"
)

func TestIsLocal(t *testing.T) {
	local := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	for s, want := range map[string]bool{
		"127.0.0.1":          true,
		"::1":                true,
		"10.1.2.3":           true,
		"172.16.0.1":         true,
		"172.32.0.1":         false,
		"192.168.1.1":        true,
		"fd00::1":            true,
		"fe80::1":            true,
		"169.254.1.1":        true,
		"100.64.0.1":         true,
		"100.128.0.1":        false,
		"198.51.100.7":       true,
		"203.0.113.5":        false,
		"2001:db8::1":        false,
		"::ffff:192.168.1.1": true,
	} {
		if got := IsLocal(netip.MustParseAddr(s), local); got != want {
			t.Errorf("IsLocal(%s) = %v, attendu %v", s, got, want)
		}
	}
	if IsLocal(netip.Addr{}, nil) {
		t.Error("adresse nulle vue locale")
	}
}

func TestLocalPrefixes(t *testing.T) {
	ps, err := LocalPrefixes()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range ps {
		if !p.IsValid() || p.Bits() > p.Addr().BitLen() {
			t.Errorf("préfixe invalide %v", p)
		}
	}
}

func TestCDN(t *testing.T) {
	for s, want := range map[string]string{
		"173.245.48.1":      "cloudflare",
		"2606:4700::1":      "cloudflare",
		"151.101.1.1":       "fastly",
		"35.191.0.1":        "google",
		"203.0.113.1":       "",
		"192.0.2.1":         "",
		"::ffff:104.16.0.1": "cloudflare",
	} {
		got, ok := CDN(netip.MustParseAddr(s))
		if got != want || ok != (want != "") {
			t.Errorf("CDN(%s) = %q,%v ; attendu %q", s, got, ok, want)
		}
	}
	for _, name := range []string{"cloudflare", "fastly", "cloudfront", "google", "bunny"} {
		ps := CDNPrefixes(name)
		if len(ps) == 0 {
			t.Errorf("%s : aucune plage embarquée", name)
		}
		// Chaque fournisseur reconnaît sa dernière plage (pas de masquage par un autre).
		if got, _ := CDN(ps[len(ps)-1].Addr()); got != name {
			t.Errorf("%s : dernière plage attribuée à %q", name, got)
		}
	}
	if CDNPrefixes("inconnu") != nil {
		t.Error("fournisseur inconnu")
	}
	ps := CDNPrefixes("cloudflare")
	ps[0] = netip.Prefix{}
	if !CDNPrefixes("cloudflare")[0].IsValid() {
		t.Error("CDNPrefixes doit renvoyer une copie")
	}
	if p, ok := CDNOverlap(netip.MustParsePrefix("0.0.0.0/0")); !ok || p == "" {
		t.Error("0.0.0.0/0 chevauche forcément un CDN")
	}
	if _, ok := CDNOverlap(netip.MustParsePrefix("203.0.113.0/24")); ok {
		t.Error("plage de documentation vue CDN")
	}
}
