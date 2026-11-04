package kb

import (
	"strings"
	"testing"
)

const ids = `chain.allowlist.wide chain.duplicate-host chain.exposed chain.exposure chain.problem chain.template.missing dns.caa.absent
dns.caa.info dns.dmarc.absent dns.dmarc.no-rua dns.dmarc.p-none dns.dnssec.absent dns.dnssec.invalid dns.dnssec.unknown
dns.ipv6.absent dns.mta-sts.absent dns.mta-sts.invalid dns.mx dns.no-cdn dns.nomail.dmarc dns.nomail.spf dns.null-mx
dns.origin-exposed dns.private-answer dns.resolve.fail dns.spf.absent dns.spf.multiple dns.spf.plus-all
dns.spf.softfail-all dns.spf.too-many-lookups dns.tlsrpt.absent http.alpn.h2 http.alpn.h2-absent
http.cache.private-cacheable http.compression.secret http.cookie.no-httponly.sid http.cookie.no-samesite.sid
http.cookie.no-secure.sid http.cookie.prefix-invalid.__Host-x http.cookie.samesite-none.t http.coop.absent http.corp.absent
http.cors.null-origin http.cors.reflect-origin http.cors.wildcard-credentials http.csp.absent http.csp.no-frame-ancestors
http.csp.no-script-src http.csp.unsafe-eval http.csp.unsafe-inline http.csp.wildcard http.error.verbose
http.h3.advertised http.h3.broken http.h3.ok http.hsts.absent http.hsts.no-subdomains http.hsts.preload-ready
http.hsts.short http.leak.ds-store http.leak.env http.leak.git http.leak.phpinfo http.leak.server-info http.leak.server-status
http.method.list http.method.trace http.mixed-content http.nosniff.absent http.permissions.absent http.redirect.chain-long
http.redirect.https http.redirect.insecure-hop http.referrer.absent http.referrer.unsafe http.robots http.securitytxt.absent
http.server.version http.sri.missing http.sse.unprotected http.tech http.tls.unverified http.unreachable http.ws.open
http.ws.unprotected http.xfo.absent parity.no-route parity.v4v6 parity.v4v6.unreachable port.local-vantage port.open
port.risky.postgres port.ssh.version port.ssh.weak-cipher port.ssh.weak-hostkey port.ssh.weak-kex port.ssh.weak-mac
scan.panic tls.cert.chain-incomplete tls.cert.expired tls.cert.expires-soon tls.cert.info tls.cert.lint.e_foo
tls.cert.name-mismatch tls.cert.sha1 tls.cert.untrusted tls.cert.weak-key tls.cipher.3des tls.cipher.anon
tls.cipher.cbc-sha1 tls.cipher.des tls.cipher.export tls.cipher.list.tls12 tls.cipher.list.tls13 tls.cipher.no-pfs
tls.cipher.null tls.cipher.order.tls12 tls.cipher.rc4 tls.default-cert tls.error tls.groups tls.ocsp.no-stapling
tls.protocol.sslv3 tls.protocol.tls10 tls.protocol.tls11 tls.protocol.tls13.absent
cf.ssl.off cf.ssl.flexible cf.ssl.full cf.tls.min cf.https.not-forced cf.hsts.off cf.aop.off
cf.dnssec.off cf.dns.unproxied cf.dns.origin-exposed cf.waf.summary cf.token.scope cf.zone.missing`

func TestAllIDs(t *testing.T) {
	for _, id := range strings.Fields(ids) {
		en, ok := Lookup(id)
		if !ok {
			t.Errorf("%s : introuvable", id)
			continue
		}
		if en.Title == "" || en.Risk == "" {
			t.Errorf("%s : titre ou risque vide", id)
		}
	}
}

func TestPrefixAndMisses(t *testing.T) {
	a, _ := Lookup("http.cookie.no-secure.a.b")
	b, _ := Lookup("http.cookie.no-secure.")
	if a.Title != b.Title || a.Title == "" {
		t.Error("nom de cookie avec point non résolu")
	}
	for _, id := range []string{"", "inconnu", "http.zzz", "dns", "http.hsts.absent.x"} {
		if _, ok := Lookup(id); ok {
			t.Errorf("%q ne devrait pas exister", id)
		}
	}
}

func TestEntriesWellFormed(t *testing.T) {
	ok := map[string]bool{"traefik": true, "caddy": true, "nginx": true, "npm": true, "cloudflare": true, "général": true}
	for _, tab := range tables {
		for k, en := range tab {
			if en.Title == "" || en.Risk == "" {
				t.Errorf("%s : titre ou risque vide", k)
			}
			for _, f := range en.Fixes {
				if !ok[f.Proxy] || f.Label == "" || f.Code == "" || strings.Contains(f.Code, "¤") {
					t.Errorf("%s : correctif mal formé %+v", k, f)
				}
			}
		}
	}
}
