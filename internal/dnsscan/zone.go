package dnsscan

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

// Points d'injection des tests : le vrai port HTTPS et la confiance TLS.
var (
	mtaSTSPort = 443
	mtaSTSTLS  *tls.Config
)

func (s *scanner) checkZone(zone string) {
	apex := dns.Fqdn(zone)
	target := zone
	s.checkDNSSEC(apex)

	if m, err := s.q(apex, dns.TypeCAA, false); err == nil && m.Rcode == dns.RcodeSuccess {
		if caa := pick[*dns.CAA](m, apex); len(caa) == 0 {
			s.add("dns.caa.absent", target, check.Low, "Aucun enregistrement CAA", "n'importe quelle autorité peut émettre un certificat")
		} else {
			var l []string
			for _, c := range caa {
				l = append(l, fmt.Sprintf("%d %s %q", c.Flag, c.Tag, c.Value))
			}
			s.add("dns.caa.info", target, check.Info, "CAA présent", strings.Join(l, " ; "))
		}
	}
	s.checkMail(apex, target)
}

// txt renvoie les enregistrements TXT d'un nom ; ok=false si la réponse est inexploitable
// (réseau, SERVFAIL) : on ne conclut alors pas à une absence.
func (s *scanner) txt(name string) (out []string, ok bool) {
	m, err := s.q(name, dns.TypeTXT, false)
	if err != nil || (m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError) {
		return nil, false
	}
	for _, t := range pick[*dns.TXT](m, dns.Fqdn(name)) {
		out = append(out, strings.Join(t.Txt, ""))
	}
	return out, true
}

func withPrefix(recs []string, prefix string) []string {
	var out []string
	for _, r := range recs {
		if len(r) >= len(prefix) && strings.EqualFold(r[:len(prefix)], prefix) {
			out = append(out, r)
		}
	}
	return out
}

func (s *scanner) checkMail(apex, target string) {
	m, err := s.q(apex, dns.TypeMX, false)
	if err != nil || m.Rcode != dns.RcodeSuccess {
		return
	}
	mx := pick[*dns.MX](m, apex)
	nullMX := len(mx) == 1 && mx[0].Mx == "."
	hasMail := len(mx) > 0 && !nullMX
	txts, txtOK := s.txt(apex)
	spf := withPrefix(txts, "v=spf1")
	dm, dmOK := s.txt("_dmarc." + apex)
	dmarc := withPrefix(dm, "v=DMARC1")

	if !hasMail {
		if nullMX {
			s.add("dns.null-mx", target, check.Info, "MX nul : la zone déclare ne pas recevoir de courrier", "MX 0 .")
		}
		if txtOK && (len(spf) != 1 || !strings.EqualFold(strings.Join(strings.Fields(spf[0]), " "), "v=spf1 -all")) {
			s.add("dns.nomail.spf", target, check.Low, "Zone sans courrier : SPF « v=spf1 -all » recommandé", firstOr(spf, "aucun SPF"))
		}
		if dmOK && (len(dmarc) == 0 || tag(dmarc[0], "p") != "reject") {
			s.add("dns.nomail.dmarc", target, check.Low, "Zone sans courrier : DMARC p=reject recommandé", firstOr(dmarc, "aucun DMARC"))
		}
		return
	}
	var l []string
	for _, r := range mx {
		l = append(l, fmt.Sprintf("%d %s", r.Preference, r.Mx))
	}
	s.add("dns.mx", target, check.Info, "Serveurs de courrier", strings.Join(l, " ; "))

	if txtOK {
		s.checkSPF(target, spf)
	}
	if dmOK {
		s.checkDMARC(target, dmarc)
	}
	s.checkMTASTS(apex, target)
	if t, ok := s.txt("_smtp._tls." + apex); ok && len(withPrefix(t, "v=TLSRPTv1")) == 0 {
		s.add("dns.tlsrpt.absent", target, check.Low, "TLS-RPT absent : pas de rapports d'échec TLS entre serveurs de courrier", "_smtp._tls."+strings.TrimSuffix(apex, "."))
	}
}

func firstOr(l []string, def string) string {
	if len(l) > 0 {
		return l[0]
	}
	return def
}

// tag extrait la valeur d'une étiquette DMARC (p, rua…).
func tag(rec, name string) string {
	for _, part := range strings.Split(rec, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func (s *scanner) checkDMARC(target string, dmarc []string) {
	switch {
	case len(dmarc) == 0:
		s.add("dns.dmarc.absent", target, check.Medium, "DMARC absent : l'usurpation de l'expéditeur n'est pas sanctionnée", "_dmarc."+target)
		return
	case tag(dmarc[0], "p") == "none":
		s.add("dns.dmarc.p-none", target, check.Low, "DMARC en p=none : surveillance seule, rien n'est rejeté", dmarc[0])
	}
	if tag(dmarc[0], "rua") == "" {
		s.add("dns.dmarc.no-rua", target, check.Info, "DMARC sans adresse de rapports agrégés (rua)", dmarc[0])
	}
}

func (s *scanner) checkSPF(target string, spf []string) {
	switch {
	case len(spf) == 0:
		s.add("dns.spf.absent", target, check.Medium, "SPF absent", "aucun enregistrement TXT v=spf1")
		return
	case len(spf) > 1:
		s.add("dns.spf.multiple", target, check.Medium, "Plusieurs enregistrements SPF : erreur permanente, SPF ignoré", strings.Join(spf, " | "))
		return
	}
	fields := strings.Fields(spf[0])
	for _, f := range fields[1:] {
		if strings.EqualFold(f, "+all") || strings.EqualFold(f, "all") {
			s.add("dns.spf.plus-all", target, check.High, "SPF en +all : tout expéditeur est autorisé", spf[0])
		}
		if strings.EqualFold(f, "~all") || strings.EqualFold(f, "?all") {
			s.add("dns.spf.softfail-all", target, check.Low, "SPF en "+strings.ToLower(f)+" : les expéditeurs non listés ne sont pas rejetés", spf[0])
		}
	}
	budget := 0
	s.spfLookups(spf[0], 0, map[string]bool{}, &budget)
	if budget > 10 {
		s.add("dns.spf.too-many-lookups", target, check.Medium, "SPF : plus de 10 requêtes DNS, erreur permanente", strconv.Itoa(budget)+" requêtes")
	}
}

// spfLookups compte les mécanismes qui coûtent une requête DNS (limite RFC 7208 : 10),
// en suivant include et redirect ; borné pour ne pas boucler ni exploser.
func (s *scanner) spfLookups(rec string, depth int, seen map[string]bool, n *int) {
	for _, f := range strings.Fields(rec)[1:] {
		f = strings.TrimLeft(strings.ToLower(f), "+-~?")
		i := strings.IndexAny(f, ":/=")
		mech, rest := f, ""
		if i >= 0 {
			mech, rest = f[:i], f[i+1:]
		}
		switch mech {
		case "a", "mx", "ptr", "exists":
			*n++
		case "include", "redirect":
			*n++
			if rest == "" || seen[rest] || depth >= 10 || *n > 10 {
				continue
			}
			seen[rest] = true
			if t, ok := s.txt(rest); ok {
				if r := withPrefix(t, "v=spf1"); len(r) == 1 {
					s.spfLookups(r[0], depth+1, seen, n)
				}
			}
		}
	}
}

func (s *scanner) checkMTASTS(apex, target string) {
	t, ok := s.txt("_mta-sts." + apex)
	if !ok {
		return
	}
	if len(withPrefix(t, "v=STSv1")) == 0 {
		s.add("dns.mta-sts.absent", target, check.Info, "MTA-STS absent : rien n'impose le TLS entre serveurs de courrier", "_mta-sts."+target)
		return
	}
	if reason := s.fetchPolicy("mta-sts." + strings.TrimSuffix(apex, ".")); reason != "" {
		s.add("dns.mta-sts.invalid", target, check.Medium, "MTA-STS déclaré mais la politique est inutilisable", reason)
	}
}

// fetchPolicy lit et valide la politique MTA-STS ; renvoie la raison de l'échec, ou "".
func (s *scanner) fetchPolicy(host string) string {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	tr := &http.Transport{
		TLSClientConfig: mtaSTSTLS,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			h, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return s.g.Dial(ctx, s.vantage(), h, mtaSTSPort)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/.well-known/mta-sts.txt", nil)
	if err != nil {
		return err.Error()
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := cl.Do(req)
	if err != nil {
		return "récupération impossible : " + err.Error()
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "HTTP " + resp.Status
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(ct), "text/plain") {
		return "Content-Type " + strconv.Quote(ct) + " au lieu de text/plain"
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return err.Error()
	}
	kv := map[string][]string{}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), ":"); ok {
			kv[strings.ToLower(strings.TrimSpace(k))] = append(kv[strings.ToLower(strings.TrimSpace(k))], strings.TrimSpace(v))
		}
	}
	if v := kv["version"]; len(v) != 1 || v[0] != "STSv1" {
		return "version STSv1 absente"
	}
	mode := ""
	if v := kv["mode"]; len(v) == 1 {
		mode = v[0]
	}
	if mode != "enforce" && mode != "testing" && mode != "none" {
		return "mode absent ou inconnu : " + strconv.Quote(mode)
	}
	if age, err := strconv.Atoi(firstOr(kv["max_age"], "")); err != nil || age < 0 {
		return "max_age absent ou invalide"
	}
	if mode != "none" && len(kv["mx"]) == 0 {
		return "aucune ligne mx"
	}
	return ""
}

// vantage résout par le résolveur de l'outil, pour que la politique soit lue là où il regarde.
func (s *scanner) vantage() scan.Vantage {
	return scan.Vantage{Name: "dns", Addrs: func(_ context.Context, host string) ([]netip.Addr, error) {
		var out []netip.Addr
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m, err := s.q(host, t, false)
			if err != nil {
				return nil, err
			}
			for _, rr := range m.Answer {
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
		return out, nil
	}}
}
