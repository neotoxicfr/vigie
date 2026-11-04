package tlsscan

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/netinfo"
	"github.com/neotoxicfr/vigie/internal/scan"
	zx509 "github.com/zmap/zcrypto/x509"
	"github.com/zmap/zlint/v3"
	"github.com/zmap/zlint/v3/lint"
)

var (
	roots *x509.CertPool // nil : racines du système ; remplacé par les tests
	// aiaAllowLocal : les tests servent l'AIA sur le bouclage.
	aiaAllowLocal bool
	errNoAIA      = errors.New("pas d'URL d'émetteur")
	// L'AIA est fournie par la cible : aucune redirection, et jamais d'adresse
	// interne (SSRF), sinon une cible hostile sonderait le réseau de vigie.
	aiaClient = &http.Client{
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{DialContext: aiaDial, DisableKeepAlives: true},
	}
)

func aiaDial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	for _, a := range addrs {
		a = a.Unmap()
		if !aiaAllowLocal && (netinfo.IsLocal(a, nil) || a.IsUnspecified() || a.IsMulticast()) {
			continue
		}
		return d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
	}
	return nil, errors.New("adresse refusée")
}

const day = 24 * time.Hour

func checkCert(ctx context.Context, r *report, host string, st tls.ConnectionState, now time.Time) {
	certs := st.PeerCertificates
	if len(certs) == 0 {
		return
	}
	leaf := certs[0]
	r.add("tls.cert.info", check.Info, "Certificat servi", fmt.Sprintf("émetteur : %s ; expire le %s ; SAN : %s",
		leaf.Issuer.CommonName, leaf.NotAfter.UTC().Format("2006-01-02"), strings.Join(sans(leaf), ", ")))

	switch left := leaf.NotAfter.Sub(now); {
	case left < 0:
		r.add("tls.cert.expired", check.High, "Certificat expiré", "expiré le "+leaf.NotAfter.UTC().Format(time.RFC3339))
	case left < 14*day:
		r.add("tls.cert.expires-soon", check.High, "Certificat proche de l'expiration", expiresIn(left))
	case left < 30*day:
		r.add("tls.cert.expires-soon", check.Medium, "Certificat proche de l'expiration", expiresIn(left))
	}

	incomplete, err := verifyChain(ctx, certs, now)
	switch {
	case err != nil:
		r.add("tls.cert.untrusted", check.High, "Chaîne de certificats non fiable", err.Error())
	case incomplete:
		r.add("tls.cert.chain-incomplete", check.Medium, "Chaîne incomplète (validée seulement grâce à l'AIA)",
			fmt.Sprintf("%d certificat(s) servi(s), émetteur manquant : « %s »", len(certs), certs[len(certs)-1].Issuer.CommonName))
	}

	if err := leaf.VerifyHostname(host); err != nil {
		r.add("tls.cert.name-mismatch", check.High, "Le certificat ne couvre pas le nom demandé",
			host+" absent de : "+strings.Join(sans(leaf), ", "))
	}

	var weak, sha1 []string
	for i, c := range certs {
		if w := weakKey(c); w != "" {
			weak = append(weak, label(i, c)+" : "+w)
		}
		selfSigned := bytes.Equal(c.RawIssuer, c.RawSubject)
		if (i == 0 || !selfSigned) && isSHA1(c.SignatureAlgorithm) {
			sha1 = append(sha1, label(i, c)+" : "+c.SignatureAlgorithm.String())
		}
	}
	if weak != nil {
		r.add("tls.cert.weak-key", check.High, "Clé de certificat trop courte", strings.Join(weak, " ; "))
	}
	if sha1 != nil {
		r.add("tls.cert.sha1", check.Medium, "Certificat signé en SHA-1", strings.Join(sha1, " ; "))
	}

	if len(st.OCSPResponse) == 0 {
		r.add("tls.ocsp.no-stapling", check.Info, "Pas d'agrafage OCSP", "aucune réponse OCSP jointe à la poignée de main")
	}
	lintChain(r, certs)
}

func expiresIn(d time.Duration) string {
	return fmt.Sprintf("expire dans %d jour(s)", int(d/day))
}

func label(i int, c *x509.Certificate) string {
	return fmt.Sprintf("certificat %d (%s)", i, c.Subject.CommonName)
}

func sans(c *x509.Certificate) []string {
	out := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

func weakKey(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if n := k.N.BitLen(); n < 2048 {
			return fmt.Sprintf("RSA %d bits", n)
		}
	case *ecdsa.PublicKey:
		if n := k.Curve.Params().BitSize; n < 256 {
			return fmt.Sprintf("ECDSA %d bits", n)
		}
	}
	return ""
}

func isSHA1(a x509.SignatureAlgorithm) bool {
	return a == x509.SHA1WithRSA || a == x509.ECDSAWithSHA1 || a == x509.DSAWithSHA1
}

// verifyChain vérifie la chaîne servie ; si l'émetteur manque, il suit l'AIA
// (au plus 3 sauts) : une chaîne validée ainsi est seulement incomplète. Un
// certificat expiré est vérifié à sa dernière seconde de validité, pour que
// l'expiration ne masque pas un défaut de confiance.
func verifyChain(ctx context.Context, certs []*x509.Certificate, now time.Time) (incomplete bool, err error) {
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if now.After(leaf.NotAfter) {
		now = leaf.NotAfter.Add(-time.Second)
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: now}
	_, err = leaf.Verify(opts)
	var ua x509.UnknownAuthorityError
	if !errors.As(err, &ua) {
		return false, err
	}
	cur := certs[len(certs)-1]
	for range 3 {
		next, ferr := fetchIssuer(ctx, cur)
		if ferr != nil {
			if errors.Is(ferr, errNoAIA) {
				return false, fmt.Errorf("%v (AIA : %v)", err, ferr)
			}
			return false, fmt.Errorf("%v (AIA : échec)", err)
		}
		inter.AddCert(next)
		if _, verr := leaf.Verify(opts); verr == nil {
			return true, nil
		}
		cur = next
	}
	return false, fmt.Errorf("%v (AIA : récupéré)", err)
}

func fetchIssuer(ctx context.Context, c *x509.Certificate) (*x509.Certificate, error) {
	i := slices.IndexFunc(c.IssuingCertificateURL, func(u string) bool { return strings.HasPrefix(u, "http://") })
	if i < 0 {
		return nil, errNoAIA
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.IssuingCertificateURL[i], nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := aiaClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("statut inattendu")
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// lintChain passe chaque certificat servi dans zlint ; un même lint sur
// plusieurs certificats donne un seul constat, à la sévérité la plus haute.
func lintChain(r *report, certs []*x509.Certificate) {
	type hit struct {
		sev check.Severity
		ev  []string
	}
	hits := map[string]*hit{}
	for i, c := range certs {
		zc, err := zx509.ParseCertificate(c.Raw)
		if err != nil {
			continue
		}
		for name, res := range zlint.LintCertificate(zc).Results {
			var sev check.Severity
			switch res.Status {
			case lint.Error, lint.Fatal:
				sev = check.Medium
			case lint.Warn:
				// Avertissement de forme sur un certificat émis par une AC : rien que
				// l'exploitant puisse corriger, donc information.
				sev = check.Info
			default:
				continue
			}
			h := hits[name]
			if h == nil {
				h = &hit{sev: sev}
				hits[name] = h
			}
			h.sev = max(h.sev, sev)
			ev := label(i, c)
			if res.Details != "" {
				ev += " : " + res.Details
			}
			h.ev = append(h.ev, ev)
		}
	}
	names := make([]string, 0, len(hits))
	for n := range hits {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		r.add("tls.cert.lint."+n, hits[n].sev, "Certificat non conforme (zlint "+n+")", strings.Join(hits[n].ev, " ; "))
	}
}

// defaultCert décrit le certificat servi sans SNI et signale les noms qu'il
// révèle en plus de host.
func defaultCert(r *report, host string, withSNI, def tls.ConnectionState, err error) {
	if err != nil || len(def.PeerCertificates) == 0 {
		r.add("tls.default-cert", check.Info, "Aucun certificat servi sans SNI", "poignée de main sans SNI refusée")
		return
	}
	leaf := def.PeerCertificates[0]
	var others []string
	for _, n := range sans(leaf) {
		if !strings.EqualFold(n, host) && !wildcardMatch(n, host) {
			others = append(others, n)
		}
	}
	same := len(withSNI.PeerCertificates) > 0 && withSNI.PeerCertificates[0].Equal(leaf)
	title := "Certificat par défaut (sans SNI)"
	ev := "SAN : " + strings.Join(sans(leaf), ", ")
	if same {
		ev = "même certificat qu'avec SNI ; " + ev
	}
	if len(others) > 0 {
		title = "Le certificat par défaut révèle d'autres noms"
		ev = "autres noms que " + host + " : " + strings.Join(others, ", ") + " ; " + ev
	}
	r.add("tls.default-cert", check.Info, title, ev)
}

func wildcardMatch(pattern, host string) bool {
	rest, ok := strings.CutPrefix(pattern, "*.")
	if !ok {
		return false
	}
	_, after, found := strings.Cut(host, ".")
	return found && strings.EqualFold(after, rest)
}
