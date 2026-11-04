// Package tlsscan contrôle la configuration TLS d'une cible : protocoles,
// suites, groupes, certificat servi avec et sans SNI.
package tlsscan

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

// maxConns borne les connexions d'un Scan, énumération comprise.
const maxConns = 64

var errBudget = errors.New("budget de connexions de la cible épuisé")

type prober struct {
	g    *scan.Guard
	v    scan.Vantage
	host string
	port int
	n    int
}

func (p *prober) dial(ctx context.Context) (net.Conn, error) {
	if p.n >= maxConns {
		return nil, errBudget
	}
	p.n++
	return p.g.Dial(ctx, p.v, p.host, p.port)
}

// sni vaut l'hôte, sauf pour une IP littérale (interdite dans SNI).
func (p *prober) sni() string {
	if _, err := netip.ParseAddr(p.host); err == nil {
		return ""
	}
	return p.host
}

// std fait une poignée de main crypto/tls complète ; la vérification est faite
// à part (cert.go) pour pouvoir qualifier chaque défaut.
func (p *prober) std(ctx context.Context, cfg *tls.Config) (tls.ConnectionState, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline(ctx))
	cfg.InsecureSkipVerify = true
	c := tls.Client(conn, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		return tls.ConnectionState{}, err
	}
	return c.ConnectionState(), nil
}

type report struct {
	target, vantage string
	out             []check.Finding
}

func (r *report) add(id string, sev check.Severity, title, evidence string) {
	r.out = append(r.out, check.Finding{Check: id, Target: r.target, Vantage: r.vantage,
		Severity: sev, Title: title, Evidence: clip(evidence)})
}

// clip borne une preuve à 300 caractères.
func clip(s string) string {
	r := []rune(s)
	if len(r) <= 300 {
		return s
	}
	return string(r[:299]) + "…"
}

// Scan contrôle host:port depuis le point de vue v ; host sert de SNI. Toutes
// les connexions passent par g, au plus 64 pour la cible.
func Scan(ctx context.Context, g *scan.Guard, v scan.Vantage, host string, port int) []check.Finding {
	p := &prober{g: g, v: v, host: host, port: port}
	r := &report{target: net.JoinHostPort(host, strconv.Itoa(port)), vantage: v.Name}
	st, stdErr := certPart(ctx, p, r)

	accepted := map[uint16][]uint16{}
	truncated := map[uint16]bool{}
	for _, vers := range []uint16{versionTLS13, versionTLS12, versionTLS11, versionTLS10, versionSSL30} {
		offer := legacySuites
		if vers == versionTLS13 {
			offer = tls13Suites
		}
		a, t := p.enumerate(ctx, vers, offer)
		truncated[vers] = t
		if len(a) > 0 {
			accepted[vers] = a
		}
	}
	// zcrypto peut échouer en TLS 1.3 là où crypto/tls réussit : on garde au moins ce que crypto/tls a vu.
	if stdErr == nil && accepted[st.Version] == nil {
		accepted[st.Version] = []uint16{st.CipherSuite}
	}

	if len(accepted) == 0 {
		err := stdErr
		if err == nil {
			err = errors.New("aucune version acceptée")
		}
		r.add("tls.error", check.Info, "Poignée de main TLS impossible", err.Error())
		return r.out
	}

	protocols(r, accepted)
	ciphers(ctx, r, p, accepted, truncated)
	groups(ctx, r, p, accepted)
	return r.out
}

// certPart : certificat de l'hôte et certificat par défaut (sans SNI).
func certPart(ctx context.Context, p *prober, r *report) (tls.ConnectionState, error) {
	st, stdErr := p.std(ctx, &tls.Config{ServerName: p.sni(), MinVersion: tls.VersionTLS10})
	if stdErr == nil {
		checkCert(ctx, r, p.host, st, time.Now())
	}
	if p.sni() != "" && stdErr == nil {
		def, err := p.std(ctx, &tls.Config{MinVersion: tls.VersionTLS10})
		defaultCert(r, p.host, st, def, err)
	}
	return st, stdErr
}

// scanCertOnly : la partie propre à l'hôte, quand l'énumération est reprise du cache.
func scanCertOnly(ctx context.Context, g *scan.Guard, v scan.Vantage, host string, port int) []check.Finding {
	p := &prober{g: g, v: v, host: host, port: port}
	r := &report{target: net.JoinHostPort(host, strconv.Itoa(port)), vantage: v.Name}
	if _, err := certPart(ctx, p, r); err != nil {
		r.add("tls.error", check.Info, "Poignée de main TLS impossible", err.Error())
	}
	return r.out
}

func protocols(r *report, accepted map[uint16][]uint16) {
	if accepted[versionSSL30] != nil {
		r.add("tls.protocol.sslv3", check.High, "SSLv3 accepté", "le serveur répond en SSLv3 (POODLE)")
	}
	if accepted[versionTLS10] != nil {
		r.add("tls.protocol.tls10", check.Medium, "TLS 1.0 accepté", "le serveur répond en TLS 1.0, obsolète (RFC 8996)")
	}
	if accepted[versionTLS11] != nil {
		r.add("tls.protocol.tls11", check.Medium, "TLS 1.1 accepté", "le serveur répond en TLS 1.1, obsolète (RFC 8996)")
	}
	if accepted[versionTLS13] == nil {
		r.add("tls.protocol.tls13.absent", check.Low, "TLS 1.3 non proposé", "aucune poignée de main TLS 1.3 aboutie")
	}
}

var graveTitles = map[string]string{
	"null":   "Suites sans chiffrement (NULL) acceptées",
	"anon":   "Suites anonymes, sans authentification, acceptées",
	"export": "Suites EXPORT acceptées",
	"rc4":    "Suites RC4 acceptées",
	"des":    "Suites DES acceptées",
	"3des":   "Suites 3DES acceptées (Sweet32)",
}

var order = []uint16{versionTLS13, versionTLS12, versionTLS11, versionTLS10, versionSSL30}

func ciphers(ctx context.Context, r *report, p *prober, accepted map[uint16][]uint16, truncated map[uint16]bool) {
	weak := map[string][]string{} // catégorie → « version : suites »
	for _, vers := range order {
		list := accepted[vers]
		if list == nil {
			continue
		}
		byCat := map[string][]string{}
		names := make([]string, len(list))
		for i, s := range list {
			names[i] = shortName(s)
			grave, nopfs, cbc := weakness(s)
			if grave != "" {
				byCat[grave] = append(byCat[grave], names[i])
			}
			if nopfs {
				byCat["no-pfs"] = append(byCat["no-pfs"], names[i])
			}
			if cbc {
				byCat["cbc-sha1"] = append(byCat["cbc-sha1"], names[i])
			}
		}
		for c, l := range byCat {
			weak[c] = append(weak[c], versionNames[vers]+" : "+strings.Join(l, ", "))
		}
		ev := strings.Join(names, ", ")
		if truncated[vers] {
			ev = "énumération tronquée (budget atteint) : " + ev
		}
		r.add("tls.cipher.list."+versionIDs[vers], check.Info, "Suites acceptées en "+versionNames[vers], ev)

		if server, known := p.serverOrder(ctx, vers, list); known {
			title := "Ordre des suites laissé au client en " + versionNames[vers]
			if server {
				title = "Ordre des suites imposé par le serveur en " + versionNames[vers]
			}
			r.add("tls.cipher.order."+versionIDs[vers], check.Info, title, "premier choix : "+names[0])
		}
	}
	for _, c := range []string{"null", "anon", "export", "rc4", "des", "3des"} {
		if weak[c] != nil {
			r.add("tls.cipher."+c, check.High, graveTitles[c], strings.Join(weak[c], " ; "))
		}
	}
	if weak["no-pfs"] != nil {
		r.add("tls.cipher.no-pfs", check.Medium, "Suites sans confidentialité persistante (échange RSA ou DH statique)",
			strings.Join(weak["no-pfs"], " ; "))
	}
	if weak["cbc-sha1"] != nil {
		r.add("tls.cipher.cbc-sha1", check.Low, "Suites CBC avec MAC SHA-1", strings.Join(weak["cbc-sha1"], " ; "))
	}
}

var allGroups = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}

// groups énumère par élimination les groupes d'échange acceptés, dans la plus
// haute version entre TLS 1.2 et 1.3.
func groups(ctx context.Context, r *report, p *prober, accepted map[uint16][]uint16) {
	vers := uint16(tls.VersionTLS13)
	if accepted[versionTLS13] == nil {
		if accepted[versionTLS12] == nil {
			return
		}
		vers = tls.VersionTLS12
	}
	offer := append([]tls.CurveID(nil), allGroups...)
	var got []string
	for len(offer) > 0 {
		st, err := p.std(ctx, &tls.Config{ServerName: p.sni(), MinVersion: vers, MaxVersion: vers, CurvePreferences: offer})
		if err != nil || st.CurveID == 0 {
			break
		}
		i := -1
		for j, c := range offer {
			if c == st.CurveID {
				i = j
			}
		}
		if i < 0 {
			break
		}
		got = append(got, st.CurveID.String())
		offer = append(offer[:i], offer[i+1:]...)
	}
	if len(got) > 0 {
		r.add("tls.groups", check.Info, "Groupes d'échange acceptés en "+versionNames[vers], strings.Join(got, ", "))
	}
}
