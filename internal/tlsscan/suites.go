package tlsscan

import (
	"context"
	"fmt"
	"strings"
	"time"

	ztls "github.com/zmap/zcrypto/tls"
)

const (
	versionSSL30 uint16 = 0x0300
	versionTLS10 uint16 = 0x0301
	versionTLS11 uint16 = 0x0302
	versionTLS12 uint16 = 0x0303
	versionTLS13 uint16 = 0x0304
)

var versionNames = map[uint16]string{
	versionSSL30: "SSLv3", versionTLS10: "TLS 1.0", versionTLS11: "TLS 1.1",
	versionTLS12: "TLS 1.2", versionTLS13: "TLS 1.3",
}

// versionIDs donne le suffixe stable des identifiants de constats.
var versionIDs = map[uint16]string{
	versionSSL30: "sslv3", versionTLS10: "tls10", versionTLS11: "tls11",
	versionTLS12: "tls12", versionTLS13: "tls13",
}

// legacySuites : toutes les suites connues de zcrypto pour SSLv3–TLS 1.2, hors
// PSK/SRP/KRB5 (jamais choisies sans secret partagé) et signalisations SCSV.
var legacySuites = func() []uint16 {
	var out []uint16
	for id := 0; id <= 0xFFFF; id++ {
		name := ztls.CipherSuiteID(id).String()
		if name == "unknown" || id>>8 == 0x13 {
			continue
		}
		u := strings.ToUpper(name)
		if strings.Contains(u, "PSK") || strings.Contains(u, "SRP") || strings.Contains(u, "KRB5") ||
			strings.Contains(u, "SCSV") || strings.Contains(u, "RENEGO") || strings.Contains(u, "GOST") {
			continue
		}
		out = append(out, uint16(id))
	}
	return out
}()

var tls13Suites = []uint16{0x1301, 0x1302, 0x1303, 0x1304, 0x1305}

func suiteName(id uint16) string {
	n := ztls.CipherSuiteID(id).String()
	if n == "unknown" {
		return fmt.Sprintf("0x%04X", id)
	}
	return n
}

// shortName allège un nom IANA pour tenir dans une preuve courte.
func shortName(id uint16) string {
	n := strings.TrimPrefix(suiteName(id), "TLS_")
	return strings.Replace(n, "_WITH_", "_", 1)
}

// hello offre suites en version vers et renvoie la version et la suite du
// ServerHello ; ok est faux si le serveur refuse ou répond dans une autre version.
func (p *prober) hello(ctx context.Context, vers uint16, suites []uint16) (suite uint16, ok bool, err error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return 0, false, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline(ctx))
	cfg := &ztls.Config{
		ServerName:         p.sni(),
		InsecureSkipVerify: true,
		MinVersion:         vers,
		MaxVersion:         vers,
		CipherSuites:       suites,
		ForceSuites:        true,
	}
	if vers == versionSSL30 {
		// zcrypto ne négocie plus SSLv3 : un ClientHello brut suffit, seul le
		// ServerHello nous intéresse.
		var ext []ztls.ClientExtension
		if sni := p.sni(); sni != "" {
			ext = append(ext, &ztls.SNIExtension{Domains: []string{sni}})
		}
		cfg.ClientFingerprintConfiguration = &ztls.ClientFingerprintConfiguration{
			HandshakeVersion:   versionSSL30,
			CipherSuites:       suites,
			CompressionMethods: []uint8{0},
			Extensions:         ext,
		}
	}
	c := ztls.Client(conn, cfg)
	_ = c.Handshake()
	log := c.GetHandshakeLog()
	if log == nil || log.ServerHello == nil {
		return 0, false, nil
	}
	sh := log.ServerHello
	got := uint16(sh.Version)
	if sh.SupportedVersions != nil {
		got = uint16(sh.SupportedVersions.SelectedVersion)
	}
	if got != vers {
		return 0, false, nil
	}
	return uint16(sh.CipherSuite), true, nil
}

// enumerate retire une à une les suites choisies par le serveur : N+1 connexions.
func (p *prober) enumerate(ctx context.Context, vers uint16, offer []uint16) (accepted []uint16, truncated bool) {
	offer = append([]uint16(nil), offer...)
	for len(offer) > 0 {
		s, ok, err := p.hello(ctx, vers, offer)
		if err != nil {
			return accepted, true
		}
		if !ok {
			return accepted, false
		}
		i := indexOf(offer, s)
		if i < 0 { // suite non offerte : serveur fautif, on s'arrête
			return accepted, false
		}
		accepted = append(accepted, s)
		offer = append(offer[:i], offer[i+1:]...)
	}
	return accepted, false
}

// serverOrder offre les suites acceptées à l'envers : si le serveur garde son
// premier choix, c'est lui qui impose l'ordre.
func (p *prober) serverOrder(ctx context.Context, vers uint16, accepted []uint16) (server, known bool) {
	if len(accepted) < 2 {
		return false, false
	}
	rev := make([]uint16, len(accepted))
	for i, s := range accepted {
		rev[len(accepted)-1-i] = s
	}
	s, ok, err := p.hello(ctx, vers, rev)
	if err != nil || !ok {
		return false, false
	}
	return s == accepted[0], true
}

func indexOf(l []uint16, v uint16) int {
	for i, x := range l {
		if x == v {
			return i
		}
	}
	return -1
}

func deadline(ctx context.Context) time.Time {
	d := time.Now().Add(10 * time.Second)
	if t, ok := ctx.Deadline(); ok && t.Before(d) {
		return t
	}
	return d
}

// weakness classe une suite : un défaut grave (null, anon, export, rc4, des,
// 3des) prime ; nopfs et cbcSHA1 se cumulent.
func weakness(id uint16) (grave string, nopfs, cbcSHA1 bool) {
	n := strings.ToUpper(suiteName(id))
	switch {
	case strings.Contains(n, "_NULL"):
		grave = "null"
	case strings.Contains(n, "_ANON_"):
		grave = "anon"
	case strings.Contains(n, "EXPORT"):
		grave = "export"
	case strings.Contains(n, "_RC4_"):
		grave = "rc4"
	case strings.Contains(n, "3DES"):
		grave = "3des"
	case strings.Contains(n, "_DES_") || strings.Contains(n, "DES40"):
		grave = "des"
	}
	if grave != "anon" && id>>8 != 0x13 && (strings.HasPrefix(n, "TLS_RSA_") ||
		strings.HasPrefix(n, "TLS_DH_") || strings.HasPrefix(n, "TLS_ECDH_")) {
		nopfs = true
	}
	cbcSHA1 = grave == "" && strings.HasSuffix(n, "_CBC_SHA")
	return
}
