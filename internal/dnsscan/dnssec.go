package dnsscan

import (
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/neotoxicfr/vigie/internal/check"
)

// Ancres de confiance IANA (KSK-2017 et KSK-2024 de la racine). Variable pour que
// les tests y mettent la clé de leur racine fictive.
var anchors = rootAnchors()

func rootAnchors() map[string][]*dns.DS {
	var out []*dns.DS
	for _, s := range []string{
		". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
		". IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
	} {
		out = append(out, dns.Copy(mustRR(s)).(*dns.DS))
	}
	return map[string][]*dns.DS{".": out}
}

func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

type status int

const (
	secure status = iota
	insecure
	bogus
	unknown // résolveur injoignable : on ne conclut pas
)

type zstate struct {
	st     status
	reason string
	keys   []*dns.DNSKEY
}

type cutRes struct {
	name string
	err  error
}

func parentName(name string) string {
	l := dns.SplitDomainName(name)
	if len(l) <= 1 {
		return "."
	}
	return dns.Fqdn(strings.Join(l[1:], "."))
}

// cutOf renvoie le sommet de zone le plus proche, au nom ou au-dessus (un nom
// n'est un sommet que si une requête SOA le renvoie à son propre nom).
func (s *scanner) cutOf(name string) (string, error) {
	name = strings.ToLower(dns.Fqdn(name))
	if c, ok := s.cuts[name]; ok {
		return c.name, c.err
	}
	var res cutRes
	if name == "." {
		res = cutRes{name: "."}
	} else if m, err := s.q(name, dns.TypeSOA, false); err != nil {
		res = cutRes{err: err}
	} else if len(pick[*dns.SOA](m, name)) > 0 {
		res = cutRes{name: name}
	} else {
		n, err := s.cutOf(parentName(name))
		res = cutRes{n, err}
	}
	s.cuts[name] = res
	return res.name, res.err
}

// verify vérifie qu'une signature valide de signer couvre l'ensemble rrs.
func verify(rrs []dns.RR, sigs []*dns.RRSIG, keys []*dns.DNSKEY, signer string) error {
	if len(rrs) == 0 {
		return fmt.Errorf("ensemble vide")
	}
	last := fmt.Errorf("aucune signature")
	now := time.Now()
	for _, sig := range sigs {
		if !strings.EqualFold(sig.SignerName, signer) {
			continue
		}
		if !sig.ValidityPeriod(now) {
			last = fmt.Errorf("signature hors période de validité (%s)", dns.TimeToString(sig.Expiration))
			continue
		}
		for _, k := range keys {
			if k.KeyTag() != sig.KeyTag || k.Algorithm != sig.Algorithm || k.Flags&dns.ZONE == 0 {
				continue
			}
			err := sig.Verify(k, rrs)
			if err == nil {
				return nil
			}
			last = fmt.Errorf("signature invalide (%v)", err)
		}
	}
	return last
}

func sigsFor(m *dns.Msg, owner string, t uint16) []*dns.RRSIG {
	var out []*dns.RRSIG
	for _, sg := range pick[*dns.RRSIG](m, owner) {
		if sg.TypeCovered == t {
			out = append(out, sg)
		}
	}
	return out
}

func toRRs[T dns.RR](in []T) []dns.RR {
	out := make([]dns.RR, len(in))
	for i, r := range in {
		out[i] = r
	}
	return out
}

// zone valide la chaîne de confiance de la zone z (un sommet de zone) depuis une
// ancre : DS chez le parent signé par les clés du parent, DNSKEY correspondant au
// DS et signé par lui. L'absence de DS n'est pas prouvée (NSEC/NSEC3 non vérifiés).
func (s *scanner) zone(z string) *zstate {
	if st, ok := s.zones[z]; ok {
		return st
	}
	st := s.validate(z)
	s.zones[z] = st
	return st
}

func (s *scanner) validate(z string) *zstate {
	ds, anchored := anchors[z]
	if !anchored {
		if z == "." {
			return &zstate{st: bogus, reason: "aucune ancre de confiance pour la racine"}
		}
		pz, err := s.cutOf(parentName(z))
		if err != nil {
			return &zstate{st: unknown, reason: err.Error()}
		}
		ps := s.zone(pz)
		if ps.st != secure {
			return ps
		}
		m, err := s.q(z, dns.TypeDS, true)
		if err != nil {
			return &zstate{st: unknown, reason: err.Error()}
		}
		ds = pick[*dns.DS](m, z)
		if len(ds) == 0 {
			return &zstate{st: insecure, reason: "aucun DS chez le parent " + pz}
		}
		if err := verify(toRRs(ds), sigsFor(m, z, dns.TypeDS), ps.keys, pz); err != nil {
			return &zstate{st: bogus, reason: "DS non vérifiable : " + err.Error()}
		}
	}
	m, err := s.q(z, dns.TypeDNSKEY, true)
	if err != nil {
		return &zstate{st: unknown, reason: err.Error()}
	}
	keys := pick[*dns.DNSKEY](m, z)
	if len(keys) == 0 {
		return &zstate{st: bogus, reason: "DS publié mais aucun DNSKEY"}
	}
	var entry []*dns.DNSKEY
	for _, k := range keys {
		for _, d := range ds {
			if k.KeyTag() != d.KeyTag || k.Algorithm != d.Algorithm {
				continue
			}
			if c := k.ToDS(d.DigestType); c != nil && strings.EqualFold(c.Digest, d.Digest) {
				entry = append(entry, k)
			}
		}
	}
	if len(entry) == 0 {
		return &zstate{st: bogus, reason: "aucun DNSKEY ne correspond au DS"}
	}
	if err := verify(toRRs(keys), sigsFor(m, z, dns.TypeDNSKEY), entry, z); err != nil {
		return &zstate{st: bogus, reason: "DNSKEY non vérifiable : " + err.Error()}
	}
	return &zstate{st: secure, keys: keys}
}

// checkDNSSEC rend le constat de DNSSEC pour l'apex ; rien si la zone est valide.
func (s *scanner) checkDNSSEC(apex string) {
	target := strings.TrimSuffix(apex, ".")
	z, err := s.cutOf(apex)
	if err != nil {
		s.add("dns.dnssec.unknown", target, check.Info, "DNSSEC non évalué", err.Error())
		return
	}
	st := s.zone(z)
	switch st.st {
	case insecure:
		s.add("dns.dnssec.absent", target, check.Low, "Zone non signée (DNSSEC absent)", st.reason)
	case bogus:
		s.add("dns.dnssec.invalid", target, check.High, "DNSSEC invalide : la zone est injoignable pour un résolveur validant", st.reason)
	case unknown:
		s.add("dns.dnssec.unknown", target, check.Info, "DNSSEC non évalué", st.reason)
	case secure:
		reason := s.checkSigned(apex, z, st)
		switch {
		case reason == "":
		case strings.Contains(reason, "aucune signature"):
			// Chaîne validée mais réponse non signée : un résolveur local qui réécrit
			// (DNS divisé, bloqueur) ou filtre les RRSIG, pas une zone cassée.
			s.add("dns.dnssec.unknown", target, check.Info, "Réponse non signée alors que la zone est signée",
				reason+" : le résolveur réécrit ou filtre sans doute la réponse ; règle scan.resolver sur un résolveur public validant pour vérifier")
		default:
			s.add("dns.dnssec.invalid", target, check.High, "DNSSEC invalide : la zone est injoignable pour un résolveur validant", reason)
		}
	}
}

// checkSigned vérifie les signatures du SOA et de l'A de l'apex avec les clés validées.
func (s *scanner) checkSigned(apex, z string, st *zstate) string {
	m, err := s.q(z, dns.TypeSOA, true)
	if err != nil {
		return ""
	}
	soa := pick[*dns.SOA](m, z)
	if len(soa) == 0 {
		return ""
	}
	if err := verify(toRRs(soa), sigsFor(m, z, dns.TypeSOA), st.keys, z); err != nil {
		return "SOA : " + err.Error()
	}
	m, err = s.q(apex, dns.TypeA, true)
	if err != nil {
		return ""
	}
	if a := pick[*dns.A](m, apex); len(a) > 0 {
		if err := verify(toRRs(a), sigsFor(m, apex, dns.TypeA), st.keys, z); err != nil {
			return "A de l'apex : " + err.Error()
		}
	}
	return ""
}
