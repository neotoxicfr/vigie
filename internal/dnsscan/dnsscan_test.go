package dnsscan

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

type signer struct {
	name string
	key  *dns.DNSKEY
	priv crypto.Signer
}

func newSigner(t *testing.T, name string) *signer {
	t.Helper()
	k := &dns.DNSKEY{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags: 257, Protocol: 3, Algorithm: dns.ECDSAP256SHA256}
	priv, err := k.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{name, k, priv.(crypto.Signer)}
}

func (sg *signer) sign(t *testing.T, rrs []dns.RR, mode string) *dns.RRSIG {
	now := time.Now()
	s := &dns.RRSIG{Hdr: dns.RR_Header{Name: rrs[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm: sg.key.Algorithm, SignerName: sg.name, KeyTag: sg.key.KeyTag(),
		Inception: uint32(now.Add(-time.Hour).Unix()), Expiration: uint32(now.Add(24 * time.Hour).Unix())}
	if mode == "expired" {
		s.Inception, s.Expiration = uint32(now.Add(-48*time.Hour).Unix()), uint32(now.Add(-24*time.Hour).Unix())
	}
	if err := s.Sign(sg.priv, rrs); err != nil {
		t.Fatal(err)
	}
	if mode == "tamper" {
		c := "A"
		if s.Signature[0] == 'A' {
			c = "B"
		}
		s.Signature = c + s.Signature[1:]
	}
	return s
}

// world est un serveur DNS faisant autorité pour toutes les zones fictives.
type world struct {
	t     *testing.T
	mu    sync.RWMutex
	rrs   map[string][]dns.RR
	sigs  map[string][]dns.RR
	names map[string]bool
	addr  string
}

func k(name string, typ uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "|" + dns.TypeToString[typ]
}

// put enregistre des RR (même nom et type) et, si sg != nil, leur signature.
func (w *world) put(sg *signer, mode string, rrs ...dns.RR) {
	key := k(rrs[0].Header().Name, rrs[0].Header().Rrtype)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.rrs[key] = append(w.rrs[key], rrs...)
	w.names[strings.ToLower(rrs[0].Header().Name)] = true
	if sg != nil {
		w.sigs[key] = []dns.RR{sg.sign(w.t, w.rrs[key], mode)}
	}
}

func (w *world) add(sg *signer, mode string, lines ...string) {
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			w.t.Fatalf("%q : %v", l, err)
		}
		w.put(sg, mode, rr)
	}
}

// zone crée un sommet de zone. Signée (sg != nil) : DNSKEY, et DS chez le parent
// (psg) sauf si dsFrom donne la clé dont tirer un faux DS.
func (w *world) zone(name string, sg, psg *signer, soaMode string, dsFrom *signer, lines ...string) {
	w.add(sg, soaMode, fmt.Sprintf("%s 3600 IN SOA ns.example.net. h.example.net. 1 3600 600 86400 300", name))
	if sg != nil {
		w.put(sg, "", sg.key)
		if psg != nil {
			src := sg
			if dsFrom != nil {
				src = dsFrom
			}
			ds := src.key.ToDS(dns.SHA256)
			ds.Hdr.Name = name
			w.put(psg, "", ds)
		}
	}
	w.add(sg, "", lines...)
}

func (w *world) ServeDNS(rw dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	q := r.Question[0]
	key := k(q.Name, q.Qtype)
	w.mu.RLock()
	defer w.mu.RUnlock()
	do := false
	if o := r.IsEdns0(); o != nil {
		do = o.Do()
		m.SetEdns0(4096, do)
	}
	if rrs, ok := w.rrs[key]; ok {
		m.Answer = append(m.Answer, rrs...)
		if do {
			m.Answer = append(m.Answer, w.sigs[key]...)
		}
	} else if cn, ok := w.rrs[k(q.Name, dns.TypeCNAME)]; ok && q.Qtype != dns.TypeCNAME {
		m.Answer = append(m.Answer, cn...)
		if !w.names[strings.ToLower(cn[0].(*dns.CNAME).Target)] {
			m.Rcode = dns.RcodeNameError
		}
	} else if !w.names[strings.ToLower(q.Name)] {
		m.Rcode = dns.RcodeNameError
	}
	if _, udp := rw.RemoteAddr().(*net.UDPAddr); udp {
		size := 512
		if o := r.IsEdns0(); o != nil {
			size = int(o.UDPSize())
		}
		m.Truncate(size)
	}
	rw.WriteMsg(m)
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, rrs: map[string][]dns.RR{}, sigs: map[string][]dns.RR{}, names: map[string]bool{}}
	for i := 0; i < 50; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			pc.Close()
			continue
		}
		up, tp := make(chan struct{}), make(chan struct{})
		u := &dns.Server{PacketConn: pc, Handler: w, NotifyStartedFunc: func() { close(up) }}
		tc := &dns.Server{Listener: ln, Handler: w, NotifyStartedFunc: func() { close(tp) }}
		go u.ActivateAndServe()
		go tc.ActivateAndServe()
		<-up
		<-tp
		t.Cleanup(func() { u.Shutdown(); tc.Shutdown() })
		w.addr = addr
		return w
	}
	t.Fatal("pas de port libre")
	return nil
}

func guard() *scan.Guard { return scan.NewGuard(1000, 4, time.Millisecond) }

func run(t *testing.T, w *world, o Options, hosts ...string) []check.Finding {
	t.Helper()
	o.Resolver = w.addr
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Scan(ctx, guard(), o, hosts)
}

func find(fs []check.Finding, id, target string) *check.Finding {
	for i := range fs {
		if fs[i].Check == id && fs[i].Target == target {
			return &fs[i]
		}
	}
	return nil
}

func ids(fs []check.Finding, target string) string {
	var l []string
	for _, f := range fs {
		if f.Target == target {
			l = append(l, f.Check)
		}
	}
	return strings.Join(l, " ")
}

// chain monte racine + « test. » signés et pose l'ancre de confiance de la racine.
func chain(t *testing.T) (*world, *signer, *signer) {
	w := newWorld(t)
	root, tld := newSigner(t, "."), newSigner(t, "test.")
	old := anchors
	anchors = map[string][]*dns.DS{".": {root.key.ToDS(dns.SHA256)}}
	t.Cleanup(func() { anchors = old })
	w.zone(".", root, nil, "", nil)
	w.zone("test.", tld, root, "", nil)
	return w, root, tld
}

func TestDNSSEC(t *testing.T) {
	w, _, tld := chain(t)
	other := newSigner(t, "other.test.")

	good := newSigner(t, "good.test.")
	w.zone("good.test.", good, tld, "", nil, "good.test. 3600 IN A 192.0.2.1", "www.good.test. 3600 IN A 192.0.2.1")
	w.zone("plain.test.", nil, tld, "", nil, "www.plain.test. 3600 IN A 192.0.2.2")
	broken := newSigner(t, "broken.test.")
	w.zone("broken.test.", broken, tld, "tamper", nil, "www.broken.test. 3600 IN A 192.0.2.3")
	expired := newSigner(t, "expired.test.")
	w.zone("expired.test.", expired, tld, "expired", nil, "www.expired.test. 3600 IN A 192.0.2.4")
	wrongds := newSigner(t, "wrongds.test.")
	w.zone("wrongds.test.", wrongds, tld, "", other, "www.wrongds.test. 3600 IN A 192.0.2.5")
	baddigest := newSigner(t, "baddigest.test.")
	w.zone("baddigest.test.", baddigest, nil, "", nil, "www.baddigest.test. 3600 IN A 192.0.2.8")
	dd := baddigest.key.ToDS(dns.SHA256)
	dd.Hdr.Name = "baddigest.test."
	dd.Digest = "00" + dd.Digest[2:]
	w.put(tld, "", dd)
	badds := newSigner(t, "badds.test.")
	w.zone("badds.test.", badds, nil, "", nil, "www.badds.test. 3600 IN A 192.0.2.11")
	bd := badds.key.ToDS(dns.SHA256)
	bd.Hdr.Name = "badds.test."
	w.put(tld, "tamper", bd)
	unsignedA := newSigner(t, "unsigneda.test.")
	w.zone("unsigneda.test.", unsignedA, tld, "", nil, "www.unsigneda.test. 3600 IN A 192.0.2.6")
	w.mu.Lock()
	w.rrs[k("unsigneda.test.", dns.TypeA)] = []dns.RR{mustRR("unsigneda.test. 3600 IN A 192.0.2.7")} // A sans signature
	w.names["unsigneda.test."] = true
	w.mu.Unlock()

	fs := run(t, w, Options{}, "www.good.test", "www.plain.test", "www.broken.test", "www.expired.test", "www.wrongds.test", "www.unsigneda.test", "www.baddigest.test", "www.badds.test")
	for _, z := range []string{"good.test", "plain.test", "broken.test", "expired.test", "wrongds.test", "unsigneda.test"} {
		t.Log(z, "→", ids(fs, z))
	}
	for _, c := range []struct{ zone, id, evidence string }{
		{"plain.test", "dns.dnssec.absent", "DS"},
		{"broken.test", "dns.dnssec.invalid", "SOA"},
		{"expired.test", "dns.dnssec.invalid", "validité"},
		{"wrongds.test", "dns.dnssec.invalid", "ne correspond"},
		{"unsigneda.test", "dns.dnssec.unknown", "A de l'apex"}, // réponse non signée : résolveur qui réécrit, pas zone cassée
		{"baddigest.test", "dns.dnssec.invalid", "ne correspond"},
		{"badds.test", "dns.dnssec.invalid", "DS non vérifiable"},
	} {
		f := find(fs, c.id, c.zone)
		if f == nil || !strings.Contains(f.Evidence, c.evidence) {
			t.Errorf("%s : %s attendu avec %q, obtenu %+v", c.zone, c.id, c.evidence, f)
		}
	}
	if s := ids(fs, "good.test"); strings.Contains(s, "dnssec") {
		t.Errorf("zone valide signalée : %s", s)
	}
	if f := find(fs, "dns.dnssec.invalid", "broken.test"); f != nil && f.Severity != check.High {
		t.Errorf("sévérité : %v", f.Severity)
	}
}

func TestDNSSECUntrustedRoot(t *testing.T) {
	w, _, _ := chain(t)
	anchors = map[string][]*dns.DS{".": {newSigner(t, ".").key.ToDS(dns.SHA256)}} // ancre qui ne correspond pas
	w.zone("x.test.", nil, nil, "", nil, "www.x.test. 3600 IN A 192.0.2.9")
	fs := run(t, w, Options{}, "www.x.test")
	if find(fs, "dns.dnssec.invalid", "x.test") == nil {
		t.Errorf("une racine hors ancre doit donner « invalid » : %s", ids(fs, "x.test"))
	}
}

func TestHosts(t *testing.T) {
	w, _, _ := chain(t)
	w.zone("hosts.test.", nil, nil, "", nil,
		"a.hosts.test. 60 IN A 192.0.2.10",
		"b.hosts.test. 60 IN A 192.0.2.20",
		"d.hosts.test. 60 IN A 198.51.100.7",
		"d.hosts.test. 60 IN AAAA 2001:db8::7",
		"e.hosts.test. 60 IN CNAME gone.hosts.test.")
	cdn := netip.MustParseAddr("192.0.2.10")
	fs := run(t, w, Options{
		Origins: []netip.Addr{netip.MustParseAddr("198.51.100.7")},
		IsCDN:   func(a netip.Addr) bool { return a == cdn },
	}, "a.hosts.test", "b.hosts.test", "c.hosts.test", "d.hosts.test", "e.hosts.test", "192.0.2.99")

	want := map[string]bool{
		"dns.resolve.fail|c.hosts.test": true, "dns.resolve.fail|e.hosts.test": true,
		"dns.origin-exposed|d.hosts.test": true,
		"dns.no-cdn|b.hosts.test":         true, "dns.no-cdn|d.hosts.test": true,
		"dns.ipv6.absent|a.hosts.test": true, "dns.ipv6.absent|b.hosts.test": true,
	}
	got := map[string]bool{}
	for _, f := range fs {
		if strings.HasPrefix(f.Check, "dns.dnssec") || strings.HasPrefix(f.Check, "dns.caa") || strings.HasPrefix(f.Check, "dns.nomail") {
			continue
		}
		if f.Vantage != "dns" {
			t.Errorf("vantage %q", f.Vantage)
		}
		got[f.Check+"|"+f.Target] = true
	}
	for k := range want {
		if !got[k] {
			t.Errorf("manquant : %s", k)
		}
	}
	for k := range got {
		if !want[k] {
			t.Errorf("en trop : %s", k)
		}
	}
	if f := find(fs, "dns.resolve.fail", "e.hosts.test"); f != nil && !strings.Contains(f.Evidence, "CNAME") {
		t.Errorf("preuve sans CNAME : %q", f.Evidence)
	}
}

func policy(mode string) string {
	return "version: STSv1\r\nmode: " + mode + "\r\nmx: mx.example.net\r\nmax_age: 86400\r\n"
}

func TestMail(t *testing.T) {
	w, _, _ := chain(t)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.Host, "mta-sts.m-good."):
			rw.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(rw, policy("enforce"))
		case strings.HasPrefix(r.Host, "mta-sts.m-badmode."):
			rw.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(rw, policy("bogus"))
		default:
			http.NotFound(rw, r)
		}
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	oldP, oldT := mtaSTSPort, mtaSTSTLS
	mtaSTSPort = srv.Listener.Addr().(*net.TCPAddr).Port
	mtaSTSTLS = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	defer func() { mtaSTSPort, mtaSTSTLS = oldP, oldT }()

	zone := func(name string, lines ...string) {
		w.zone(name+".test.", nil, nil, "", nil, lines...)
	}
	mx := func(z string) string { return z + ".test. 60 IN MX 10 mx." + z + ".test." }
	txt := func(owner, v string) string { return fmt.Sprintf("%s.test. 60 IN TXT %q", owner, v) }
	sts := func(z string) []string {
		return []string{txt("_mta-sts."+z, "v=STSv1; id=1"), "mta-sts." + z + ".test. 60 IN A 127.0.0.1"}
	}

	zone("m-good", append(sts("m-good"),
		mx("m-good"), txt("m-good", "v=spf1 include:_spf.m-good.test -all"), txt("_spf.m-good", "v=spf1 ip4:192.0.2.0/24 -all"),
		txt("_dmarc.m-good", "v=DMARC1; p=reject; rua=mailto:r@example.net"),
		txt("_smtp._tls.m-good", "v=TLSRPTv1; rua=mailto:t@example.net"),
		`m-good.test. 60 IN CAA 0 issue "letsencrypt.org"`)...)
	zone("m-bare", mx("m-bare"))
	zone("m-soft", mx("m-soft"), txt("m-soft", "v=spf1 ~all"), txt("_dmarc.m-soft", "v=DMARC1; p=none"))
	zone("m-plus", mx("m-plus"), txt("m-plus", "v=spf1 +all"))
	zone("m-multi", mx("m-multi"), txt("m-multi", "v=spf1 -all"), txt("m-multi", "v=spf1 mx -all"))
	zone("m-many", mx("m-many"), txt("m-many", "v=spf1 include:i1.m-many.test -all"),
		txt("i1.m-many", "v=spf1 a a a a a a a a a a"))
	zone("m-ten", mx("m-ten"), txt("m-ten", "v=spf1 a a a a a a a a a a -all"))
	zone("m-badmode", append(sts("m-badmode"), mx("m-badmode"))...)
	zone("m-nopolicy", append(sts("m-nopolicy"), mx("m-nopolicy"))...)
	zone("nm-bare", "nm-bare.test. 60 IN A 192.0.2.50")
	zone("nm-ok", "nm-ok.test. 60 IN MX 0 .", txt("nm-ok", "v=spf1 -all"), txt("_dmarc.nm-ok", "v=DMARC1; p=reject"))
	big := []string{mx("m-big")}
	for i := 0; i < 30; i++ {
		big = append(big, txt("m-big", fmt.Sprintf("bruit-%02d-%s", i, strings.Repeat("x", 90))))
	}
	big = append(big, txt("m-big", "v=spf1 +all")) // en dernier : perdu si la réponse UDP est tronquée
	zone("m-big", big...)

	hosts := []string{"m-good.test", "m-bare.test", "m-soft.test", "m-plus.test", "m-multi.test", "m-many.test",
		"m-ten.test", "m-badmode.test", "m-nopolicy.test", "nm-bare.test", "nm-ok.test", "m-big.test"}
	fs := run(t, w, Options{}, hosts...)

	mail := func(z string) string {
		var l []string
		for _, f := range fs {
			if f.Target == z && (strings.HasPrefix(f.Check, "dns.") && !strings.HasPrefix(f.Check, "dns.dnssec") && !strings.HasPrefix(f.Check, "dns.resolve") && f.Check != "dns.ipv6.absent") {
				l = append(l, f.Check)
			}
		}
		return strings.Join(l, " ")
	}
	for z, want := range map[string]string{
		"m-good.test":     "dns.caa.info dns.mx",
		"m-bare.test":     "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.spf.absent dns.tlsrpt.absent",
		"m-soft.test":     "dns.caa.absent dns.dmarc.no-rua dns.dmarc.p-none dns.mta-sts.absent dns.mx dns.spf.softfail-all dns.tlsrpt.absent",
		"m-plus.test":     "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.spf.plus-all dns.tlsrpt.absent",
		"m-multi.test":    "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.spf.multiple dns.tlsrpt.absent",
		"m-many.test":     "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.spf.too-many-lookups dns.tlsrpt.absent",
		"m-ten.test":      "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.tlsrpt.absent",
		"m-badmode.test":  "dns.caa.absent dns.dmarc.absent dns.mta-sts.invalid dns.mx dns.spf.absent dns.tlsrpt.absent",
		"m-nopolicy.test": "dns.caa.absent dns.dmarc.absent dns.mta-sts.invalid dns.mx dns.spf.absent dns.tlsrpt.absent",
		"nm-bare.test":    "dns.caa.absent dns.nomail.dmarc dns.nomail.spf",
		"nm-ok.test":      "dns.caa.absent dns.null-mx",
		"m-big.test":      "dns.caa.absent dns.dmarc.absent dns.mta-sts.absent dns.mx dns.spf.plus-all dns.tlsrpt.absent",
	} {
		got := strings.Fields(mail(z))
		wantL := strings.Fields(want)
		if strings.Join(sorted(got), " ") != strings.Join(sorted(wantL), " ") {
			t.Errorf("%s :\n  obtenu  %v\n  attendu %v", z, sorted(got), sorted(wantL))
		}
	}
	if f := find(fs, "dns.spf.too-many-lookups", "m-many.test"); f != nil && !strings.Contains(f.Evidence, "11") {
		t.Errorf("preuve : %q", f.Evidence)
	}
}

func sorted(l []string) []string {
	out := append([]string{}, l...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestNoResolver(t *testing.T) {
	// résolveur qui ne répond pas : un échec par hôte, sans blocage
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	defer pc.Close()
	addr := pc.LocalAddr().String()
	pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	fs := Scan(ctx, guard(), Options{Resolver: addr}, []string{"www.example.org"})
	if find(fs, "dns.resolve.fail", "www.example.org") == nil {
		t.Fatalf("resolve.fail attendu : %+v", fs)
	}
}
