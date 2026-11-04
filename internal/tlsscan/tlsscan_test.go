package tlsscan

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

const host = "example.com"

type pki struct {
	cert *x509.Certificate
	key  crypto.Signer
}

var serial atomic.Int64

func newCert(t *testing.T, tmpl *x509.Certificate, key crypto.Signer, parent *pki) *pki {
	t.Helper()
	if key == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	tmpl.SerialNumber = big.NewInt(serial.Add(1) + 1000)
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore = time.Now().Add(-time.Hour)
	}
	if tmpl.NotAfter.IsZero() {
		tmpl.NotAfter = time.Now().Add(90 * day)
	}
	signer, issuer := key, tmpl
	if parent != nil {
		signer, issuer = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &pki{cert: c, key: key}
}

func newCA(t *testing.T, name string, parent *pki) *pki {
	return newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, NotBefore: time.Now().Add(-365 * day),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil, parent)
}

func leafTmpl(names ...string) *x509.Certificate {
	return &x509.Certificate{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
}

func tlsCert(chain ...*pki) tls.Certificate {
	c := tls.Certificate{PrivateKey: chain[0].key, Leaf: chain[0].cert}
	for _, p := range chain {
		c.Certificate = append(c.Certificate, p.cert.Raw)
	}
	return c
}

// trust remplace les racines système par ca le temps du test.
func trust(t *testing.T, ca *pki) {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	old := roots
	roots = pool
	t.Cleanup(func() { roots = old })
}

// serve accepte en boucle et passe chaque connexion à h ; il compte les connexions.
func serve(t *testing.T, h func(net.Conn)) (port int, count *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	count = new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				h(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, count
}

func serveTLS(t *testing.T, cfg *tls.Config) int {
	port, _ := serve(t, func(c net.Conn) {
		s := tls.Server(c, cfg)
		if s.Handshake() == nil {
			_, _ = io.Copy(io.Discard, s)
		}
	})
	return port
}

// serveFake répond au ClientHello par un ServerHello brut en version vers (si
// le client la propose) avec la première suite commune : ordre du serveur si
// serverOrder, sinon du client. Il permet SSLv3 et les suites que Go refuse.
func serveFake(t *testing.T, vers uint16, suites []uint16, serverOrder bool) (int, *atomic.Int64) {
	return serve(t, func(c net.Conn) {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return
		}
		body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
		if _, err := io.ReadFull(c, body); err != nil || len(body) < 39 || body[0] != 1 {
			return
		}
		h := body[4:]
		cv := binary.BigEndian.Uint16(h)
		h = h[34:]
		h = h[1+int(h[0]):]
		n := int(binary.BigEndian.Uint16(h))
		var offered []uint16
		for i := 0; i < n; i += 2 {
			offered = append(offered, binary.BigEndian.Uint16(h[2+i:]))
		}
		pick := -1
		if cv >= vers {
			a, b := offered, suites
			if serverOrder {
				a, b = suites, offered
			}
			for _, s := range a {
				if indexOf(b, s) >= 0 {
					pick = int(s)
					break
				}
			}
		}
		if pick < 0 {
			_, _ = c.Write([]byte{21, 3, 1, 0, 2, 2, 40})
			return
		}
		sh := []byte{byte(vers >> 8), byte(vers)}
		sh = append(sh, make([]byte, 32)...)
		sh = append(sh, 0, byte(pick>>8), byte(pick), 0)
		msg := append([]byte{2, 0, byte(len(sh) >> 8), byte(len(sh))}, sh...)
		rec := append([]byte{22, byte(vers >> 8), byte(vers), byte(len(msg) >> 8), byte(len(msg))}, msg...)
		_, _ = c.Write(rec)
	})
}

func run(t *testing.T, port int) map[string]check.Finding {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	g := scan.NewGuard(10000, 4, 0)
	v := scan.Fixed("origine", netip.MustParseAddr("127.0.0.1"))
	out := map[string]check.Finding{}
	for _, f := range Scan(ctx, g, v, host, port) {
		if _, dup := out[f.Check]; dup {
			t.Errorf("constat en double : %s", f.Check)
		}
		if f.Target != net.JoinHostPort(host, itoa(port)) || f.Vantage != "origine" {
			t.Errorf("cible ou point de vue faux : %+v", f)
		}
		if len([]rune(f.Evidence)) > 300 {
			t.Errorf("%s : preuve trop longue (%d)", f.Check, len([]rune(f.Evidence)))
		}
		out[f.Check] = f
	}
	return out
}

func itoa(n int) string { return big.NewInt(int64(n)).String() }

func want(t *testing.T, got map[string]check.Finding, id string, sev check.Severity, evidence string) {
	t.Helper()
	f, ok := got[id]
	if !ok {
		t.Errorf("constat %s absent ; obtenus : %v", id, keys(got))
		return
	}
	if f.Severity != sev {
		t.Errorf("%s : sévérité %v, attendu %v", id, f.Severity, sev)
	}
	if !strings.Contains(f.Evidence, evidence) {
		t.Errorf("%s : preuve %q ne contient pas %q", id, f.Evidence, evidence)
	}
}

func none(t *testing.T, got map[string]check.Finding, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if f, ok := got[id]; ok {
			t.Errorf("constat %s inattendu : %s", id, f.Evidence)
		}
	}
}

func keys(m map[string]check.Finding) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestModernServer(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	trust(t, ca)
	leaf := newCert(t, leafTmpl(host), nil, ca)
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{tlsCert(leaf, ca)}, MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256}})
	got := run(t, port)
	want(t, got, "tls.cipher.list.tls12", check.Info, "ECDHE_ECDSA_AES_128_GCM_SHA256")
	want(t, got, "tls.cipher.list.tls12", check.Info, "ECDHE_ECDSA_CHACHA20_POLY1305")
	want(t, got, "tls.cipher.list.tls13", check.Info, "AES_128_GCM_SHA256")
	want(t, got, "tls.groups", check.Info, "X25519")
	want(t, got, "tls.cert.info", check.Info, "SAN : example.com")
	want(t, got, "tls.ocsp.no-stapling", check.Info, "")
	want(t, got, "tls.default-cert", check.Info, "même certificat")
	none(t, got, "tls.protocol.sslv3", "tls.protocol.tls10", "tls.protocol.tls11", "tls.protocol.tls13.absent",
		"tls.cert.untrusted", "tls.cert.expired", "tls.cert.expires-soon", "tls.cert.name-mismatch", "tls.cert.weak-key",
		"tls.cert.sha1", "tls.cert.chain-incomplete", "tls.cipher.no-pfs", "tls.cipher.cbc-sha1", "tls.cipher.3des", "tls.error")
	if len(strings.Split(got["tls.cipher.list.tls13"].Evidence, ",")) != 3 {
		t.Errorf("TLS 1.3 : 3 suites attendues, obtenu %q", got["tls.cipher.list.tls13"].Evidence)
	}
}

func TestLegacyServer(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	trust(t, ca)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leaf := newCert(t, leafTmpl(host), k, ca)
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{tlsCert(leaf, ca)},
		MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA}})
	got := run(t, port)
	want(t, got, "tls.protocol.tls10", check.Medium, "TLS 1.0")
	want(t, got, "tls.protocol.tls11", check.Medium, "TLS 1.1")
	want(t, got, "tls.protocol.tls13.absent", check.Low, "")
	want(t, got, "tls.cipher.no-pfs", check.Medium, "TLS 1.0 : RSA_AES_128_CBC_SHA")
	want(t, got, "tls.cipher.cbc-sha1", check.Low, "RSA_AES_128_CBC_SHA")
	want(t, got, "tls.cipher.3des", check.High, "RSA_3DES_EDE_CBC_SHA")
	want(t, got, "tls.cipher.list.tls10", check.Info, "RSA_AES_128_CBC_SHA")
	want(t, got, "tls.groups", check.Info, "X25519")
	none(t, got, "tls.protocol.sslv3", "tls.cipher.list.tls13", "tls.cert.untrusted")
	if strings.Contains(got["tls.cipher.list.tls10"].Evidence, "GCM") {
		t.Errorf("GCM ne doit pas apparaître en TLS 1.0 : %s", got["tls.cipher.list.tls10"].Evidence)
	}
}

func TestWeakSuitesSSLv3(t *testing.T) {
	suites := []uint16{0x0004, 0x0003, 0x0002, 0x0018, 0x0009} // RC4_MD5, EXPORT, NULL, DH_anon, DES
	for _, serverOrder := range []bool{true, false} {
		port, _ := serveFake(t, versionSSL30, suites, serverOrder)
		got := run(t, port)
		want(t, got, "tls.protocol.sslv3", check.High, "SSLv3")
		want(t, got, "tls.cipher.rc4", check.High, "SSLv3 : RSA_RC4_128_MD5")
		want(t, got, "tls.cipher.export", check.High, "EXPORT")
		want(t, got, "tls.cipher.null", check.High, "RSA_NULL_SHA")
		want(t, got, "tls.cipher.anon", check.High, "ANON")
		want(t, got, "tls.cipher.des", check.High, "RSA_DES_CBC_SHA")
		want(t, got, "tls.cipher.no-pfs", check.Medium, "RSA_RC4_128_MD5")
		none(t, got, "tls.protocol.tls10", "tls.protocol.tls11", "tls.cipher.3des", "tls.cipher.list.tls12")
		if n := len(strings.Split(got["tls.cipher.list.sslv3"].Evidence, ",")); n != len(suites) {
			t.Errorf("%d suites SSLv3 attendues, obtenu %q", len(suites), got["tls.cipher.list.sslv3"].Evidence)
		}
		title := got["tls.cipher.order.sslv3"].Title
		if serverOrder != strings.Contains(title, "imposé") {
			t.Errorf("ordre serveur=%v, titre %q", serverOrder, title)
		}
		if serverOrder && !strings.Contains(got["tls.cipher.order.sslv3"].Evidence, "RSA_RC4_128_MD5") {
			t.Errorf("premier choix du serveur attendu : %q", got["tls.cipher.order.sslv3"].Evidence)
		}
	}
}

func TestBudget(t *testing.T) {
	port, count := serveFake(t, versionTLS12, legacySuites[:100], false)
	got := run(t, port)
	if n := count.Load(); n > maxConns {
		t.Errorf("%d connexions, budget %d", n, maxConns)
	}
	want(t, got, "tls.cipher.list.tls12", check.Info, "tronquée")
}

func TestUnreachable(t *testing.T) {
	port, _ := serve(t, func(net.Conn) {})
	got := run(t, port)
	want(t, got, "tls.error", check.Info, "")
	if len(got) != 1 {
		t.Errorf("seul tls.error attendu : %v", keys(got))
	}
}

func TestCertificates(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	now := time.Now()
	rsa1024, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	inter := newCA(t, "Intermédiaire", ca)
	aia := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(inter.cert.Raw) }))
	defer aia.Close()
	aiaAllowLocal = true
	t.Cleanup(func() { aiaAllowLocal = false })

	cases := []struct {
		name  string
		chain func() []*pki
		id    string
		sev   check.Severity
		ev    string
	}{
		{"expiré", func() []*pki {
			tm := leafTmpl(host)
			tm.NotBefore, tm.NotAfter = now.Add(-60*day), now.Add(-day)
			return []*pki{newCert(t, tm, nil, ca)}
		}, "tls.cert.expired", check.High, "expiré le"},
		{"expire sous 10 j", func() []*pki {
			tm := leafTmpl(host)
			tm.NotAfter = now.Add(10 * day)
			return []*pki{newCert(t, tm, nil, ca)}
		}, "tls.cert.expires-soon", check.High, "expire dans"},
		{"expire sous 20 j", func() []*pki {
			tm := leafTmpl(host)
			tm.NotAfter = now.Add(20 * day)
			return []*pki{newCert(t, tm, nil, ca)}
		}, "tls.cert.expires-soon", check.Medium, "expire dans 19"},
		{"nom faux", func() []*pki { return []*pki{newCert(t, leafTmpl("autre.example.org"), nil, ca)} },
			"tls.cert.name-mismatch", check.High, "autre.example.org"},
		{"RSA 1024", func() []*pki { return []*pki{newCert(t, leafTmpl(host), rsa1024, ca)} },
			"tls.cert.weak-key", check.High, "RSA 1024 bits"},
		{"zlint", func() []*pki { return []*pki{newCert(t, leafTmpl(host), rsa1024, ca)} },
			"tls.cert.lint.e_rsa_mod_less_than_2048_bits", check.Medium, "certificat 0"},
		{"autosigné", func() []*pki { return []*pki{newCert(t, leafTmpl(host), nil, nil)} },
			"tls.cert.untrusted", check.High, "unknown authority"},
		{"intermédiaire manquant", func() []*pki {
			tm := leafTmpl(host)
			tm.IssuingCertificateURL = []string{aia.URL}
			return []*pki{newCert(t, tm, nil, inter)}
		}, "tls.cert.chain-incomplete", check.Medium, "Intermédiaire"},
		{"intermédiaire manquant sans AIA", func() []*pki { return []*pki{newCert(t, leafTmpl(host), nil, inter)} },
			"tls.cert.untrusted", check.High, "pas d'URL"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trust(t, ca)
			port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{tlsCert(c.chain()...)}})
			got := run(t, port)
			want(t, got, c.id, c.sev, c.ev)
			if c.id != "tls.cert.untrusted" && c.id != "tls.cert.lint.e_rsa_mod_less_than_2048_bits" {
				none(t, got, "tls.cert.untrusted")
			}
		})
	}
}

func TestSHA1(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	trust(t, ca)
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaCA := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: "CA RSA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, k, ca)
	tm := leafTmpl(host)
	tm.SignatureAlgorithm = x509.SHA1WithRSA
	tm.SerialNumber = big.NewInt(serial.Add(1) + 1000)
	tm.NotBefore, tm.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(90*day)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, tm, rsaCA.cert, lk.Public(), k)
	if err != nil {
		t.Skipf("Go refuse de signer en SHA-1 : %v", err)
	}
	leaf, _ := x509.ParseCertificate(der)
	port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{tlsCert(&pki{leaf, lk}, rsaCA)}})
	got := run(t, port)
	want(t, got, "tls.cert.sha1", check.Medium, "SHA1-RSA")
}

func TestDefaultCert(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	trust(t, ca)
	main := tlsCert(newCert(t, leafTmpl(host), nil, ca))
	def := tlsCert(newCert(t, leafTmpl("interne.example.net", "example.com", "*.example.com"), nil, ca))
	port := serveTLS(t, &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if h.ServerName == host {
			return &main, nil
		}
		return &def, nil
	}})
	got := run(t, port)
	want(t, got, "tls.default-cert", check.Info, "autres noms que example.com : interne.example.net, *.example.com ;")
	if !strings.Contains(got["tls.default-cert"].Title, "révèle") {
		t.Errorf("titre : %q", got["tls.default-cert"].Title)
	}
}

func TestWildcard(t *testing.T) {
	if !wildcardMatch("*.example.com", "www.example.com") || wildcardMatch("*.example.com", "example.com") ||
		wildcardMatch("*.example.com", "a.b.example.com") || wildcardMatch("www.example.com", "www.example.com") {
		t.Error("wildcardMatch")
	}
}

func TestWeakness(t *testing.T) {
	cases := map[uint16][3]any{ // grave, no-pfs, cbc-sha1
		0x002F: {"", true, true},      // RSA_AES_128_CBC_SHA
		0xC013: {"", false, true},     // ECDHE_RSA_AES_128_CBC_SHA
		0xC02F: {"", false, false},    // ECDHE_RSA_AES_128_GCM
		0x000A: {"3des", true, false}, // RSA_3DES
		0x0018: {"anon", false, false},
		0xC005: {"", true, true}, // ECDH_ECDSA_AES_256_CBC_SHA : ECDH statique
		0x1301: {"", false, false},
	}
	for id, w := range cases {
		g, n, c := weakness(id)
		if g != w[0] || n != w[1] || c != w[2] {
			t.Errorf("%s : %q %v %v, attendu %v", suiteName(id), g, n, c, w)
		}
	}
}

// Une AIA hostile ne doit atteindre ni une adresse interne, ni par redirection.
func TestAIARefusesInternal(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	inter := newCA(t, "Intermédiaire", ca)
	var hits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write(inter.cert.Raw)
	}))
	defer internal.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL, http.StatusFound)
	}))
	defer redir.Close()
	for name, url := range map[string]string{"direct": internal.URL, "redirection": redir.URL} {
		t.Run(name, func(t *testing.T) {
			trust(t, ca)
			// Redirection : le bouclage est permis pour isoler le refus de suivre.
			aiaAllowLocal = name == "redirection"
			t.Cleanup(func() { aiaAllowLocal = false })
			tm := leafTmpl(host)
			tm.IssuingCertificateURL = []string{url}
			port := serveTLS(t, &tls.Config{Certificates: []tls.Certificate{tlsCert(newCert(t, tm, nil, inter))}})
			got := run(t, port)
			want(t, got, "tls.cert.untrusted", check.High, "AIA : échec")
			if strings.Contains(got["tls.cert.untrusted"].Evidence, "127.0.0.1") || hits.Load() != 0 {
				t.Errorf("AIA interne jointe (%d) : %q", hits.Load(), got["tls.cert.untrusted"].Evidence)
			}
		})
	}
}

// Deux hôtes servis par la même adresse et la même configuration : le second
// reprend l'énumération (quelques connexions au lieu de dizaines), sous son nom.
func TestCacheReuse(t *testing.T) {
	ca := newCA(t, "CA de test", nil)
	trust(t, ca)
	leaf := newCert(t, leafTmpl(host), nil, ca)
	cfg := &tls.Config{Certificates: []tls.Certificate{tlsCert(leaf, ca)}, MinVersion: tls.VersionTLS12}
	port, count := serve(t, func(c net.Conn) {
		s := tls.Server(c, cfg)
		if s.Handshake() == nil {
			_, _ = io.Copy(io.Discard, s)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	g := scan.NewGuard(10000, 4, 0)
	v := scan.Fixed("origine", netip.MustParseAddr("127.0.0.1"))
	c := NewCache()
	first := ScanCached(ctx, g, v, host, port, c)
	n1 := count.Load()
	second := ScanCached(ctx, g, v, "autre.example.com", port, c)
	n2 := count.Load() - n1
	if n2 >= n1/2 {
		t.Errorf("second hôte : %d connexions, premier : %d ; le cache n'a pas servi", n2, n1)
	}
	has := func(fs []check.Finding, id, target string) bool {
		for _, f := range fs {
			if f.Check == id && f.Target == target {
				return true
			}
		}
		return false
	}
	if !has(first, "tls.cipher.list.tls12", net.JoinHostPort(host, itoa(port))) ||
		!has(second, "tls.cipher.list.tls12", net.JoinHostPort("autre.example.com", itoa(port))) {
		t.Error("énumération absente ou mal attribuée")
	}
	if !has(second, "tls.cert.name-mismatch", net.JoinHostPort("autre.example.com", itoa(port))) {
		t.Error("le certificat du second hôte doit être contrôlé à part")
	}
}
