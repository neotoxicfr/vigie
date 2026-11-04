package portscan

import (
	"context"
	"encoding/binary"
	"github.com/miekg/dns"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

var lo = netip.MustParseAddr("127.0.0.1")

func listen(t *testing.T, handle func(net.Conn)) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); handle(c) }()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

func guard() *scan.Guard { return scan.NewGuard(100, 2, time.Millisecond) }

func byCheck(fs []check.Finding, id string) *check.Finding {
	for i := range fs {
		if fs[i].Check == id {
			return &fs[i]
		}
	}
	return nil
}

func TestOpenAndBanner(t *testing.T) {
	open := listen(t, func(c net.Conn) { c.Write([]byte("220 hello\x00\x1b[31m\r\n")) })
	// port fermé : on libère un port puis on l'utilise
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := l.Addr().(*net.TCPAddr).Port
	l.Close()

	fs := Scan(context.Background(), guard(), lo, []int{closed, open}, nil)
	if len(fs) != 1 {
		t.Fatalf("attendu 1 constat, obtenu %+v", fs)
	}
	f := fs[0]
	if f.Check != "port.open" || f.Severity != check.Info || f.Vantage != "dns" {
		t.Fatalf("constat inattendu : %+v", f)
	}
	if !strings.Contains(f.Evidence, "220 hello") || strings.ContainsAny(f.Evidence, "\x00\x1b\r\n") {
		t.Fatalf("bannière mal nettoyée : %q", f.Evidence)
	}
}

func TestRiskyAndLocal(t *testing.T) {
	p := listen(t, func(c net.Conn) {})
	services[p] = service{"redis", check.High, "test"}
	defer delete(services, p)

	fs := Scan(context.Background(), guard(), lo, []int{p}, func(netip.Addr) bool { return true })
	r := byCheck(fs, "port.risky.redis")
	if r == nil || r.Severity != check.Info { // vu seulement du LAN : information
		t.Fatalf("port.risky.redis manquant ou sévérité locale fausse : %+v", fs)
	}
	if byCheck(fs, "port.local-vantage") == nil {
		t.Fatal("port.local-vantage manquant")
	}
	for _, f := range fs {
		if !strings.Contains(f.Evidence, "non représentatif de l'extérieur") {
			t.Fatalf("preuve sans mention locale : %+v", f)
		}
	}
	// hors local : rien de tel
	fs = Scan(context.Background(), guard(), lo, []int{p}, func(netip.Addr) bool { return false })
	if byCheck(fs, "port.local-vantage") != nil || strings.Contains(fs[0].Evidence, "local") {
		t.Fatalf("mention locale à tort : %+v", fs)
	}
	if r := byCheck(fs, "port.risky.redis"); r == nil || r.Severity != check.High {
		t.Fatalf("hors local, le port risqué doit rester élevé : %+v", fs)
	}
}

func TestBudgetStops(t *testing.T) {
	p := listen(t, func(c net.Conn) {})
	fs := Scan(context.Background(), scan.NewGuard(1, 2, time.Millisecond), lo, []int{p, p, p}, nil)
	if len(fs) != 1 {
		t.Fatalf("le budget aurait dû borner à 1 constat : %+v", fs)
	}
}

func name(s string) []byte {
	b := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s)))
	return append(b, s...)
}

func kexinit(lists ...string) []byte {
	p := append([]byte{20}, make([]byte, 16)...)
	for _, l := range lists {
		p = append(p, name(l)...)
	}
	p = append(p, 0, 0, 0, 0, 0) // first_kex_follows + réservé
	pad := 8 - (len(p)+5)%8
	if pad < 4 {
		pad += 8
	}
	pkt := make([]byte, 5)
	binary.BigEndian.PutUint32(pkt, uint32(len(p)+pad+1))
	pkt[4] = byte(pad)
	pkt = append(pkt, p...)
	return append(pkt, make([]byte, pad)...)
}

func sshServer(t *testing.T, kex, host, ciph, mac string) int {
	return listen(t, func(c net.Conn) {
		c.Write([]byte("SSH-2.0-OpenSSH_9.9\r\n"))
		c.Write(kexinit(kex, host, ciph, ciph, mac, mac, "none", "none", "", ""))
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 128)
		n, _ := c.Read(buf) // notre identification
		if !strings.HasPrefix(string(buf[:n]), "SSH-2.0-vigie_") {
			t.Errorf("identification reçue : %q", buf[:n])
		}
	})
}

func TestSSH(t *testing.T) {
	weak := sshServer(t, "curve25519-sha256,diffie-hellman-group14-sha1", "ssh-ed25519,ssh-rsa",
		"aes256-ctr,aes128-cbc,3des-cbc", "hmac-sha2-256,hmac-sha1,umac-64@openssh.com")
	fs := Scan(context.Background(), guard(), lo, []int{weak}, nil)
	for _, id := range []string{"port.open", "port.ssh.version", "port.ssh.weak-kex", "port.ssh.weak-hostkey", "port.ssh.weak-cipher", "port.ssh.weak-mac"} {
		if byCheck(fs, id) == nil {
			t.Fatalf("%s manquant : %+v", id, fs)
		}
	}
	if v := byCheck(fs, "port.ssh.version"); !strings.Contains(v.Evidence, "OpenSSH_9.9") {
		t.Fatalf("version : %+v", v)
	}
	if k := byCheck(fs, "port.ssh.weak-kex"); !strings.Contains(k.Evidence, "group14-sha1") || strings.Contains(k.Evidence, "curve25519") {
		t.Fatalf("preuve kex : %+v", k)
	}
	if c := byCheck(fs, "port.ssh.weak-cipher"); !strings.Contains(c.Evidence, "aes128-cbc") || strings.Contains(c.Evidence, "aes256-ctr") {
		t.Fatalf("preuve chiffrement : %+v", c)
	}
	if o := byCheck(fs, "port.open"); strings.Contains(o.Evidence, "\x00") || strings.Contains(o.Evidence, "KEX") {
		t.Fatalf("bannière SSH : %q", o.Evidence)
	}

	good := sshServer(t, "curve25519-sha256", "ssh-ed25519", "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com",
		"hmac-sha2-512-etm@openssh.com")
	fs = Scan(context.Background(), guard(), lo, []int{good}, nil)
	for _, f := range fs {
		if strings.HasPrefix(f.Check, "port.ssh.weak") {
			t.Fatalf("faux positif : %+v", f)
		}
	}
	if byCheck(fs, "port.ssh.version") == nil {
		t.Fatal("version manquante")
	}
}

func TestReadKexInitRejects(t *testing.T) {
	if _, err := readKexInit(strings.NewReader("\xff\xff\xff\xff\x00")); err == nil {
		t.Fatal("paquet géant accepté")
	}
}

func TestDefaultPortsKnown(t *testing.T) {
	seen := map[int]bool{}
	for _, p := range DefaultPorts {
		if p < 1 || p > 65535 || seen[p] {
			t.Fatalf("port invalide ou doublon : %d", p)
		}
		seen[p] = true
	}
	for p := range services {
		if !seen[p] {
			t.Errorf("port risqué %d absent de DefaultPorts", p)
		}
	}
}

// Résolveur ouvert : signalé élevé ; serveur qui refuse la récursion : simple port ouvert.
func TestOpenResolver(t *testing.T) {
	defer func() { dnsPort = 53 }()
	for _, c := range []struct {
		recursive bool
		want      bool
	}{{true, true}, {false, false}} {
		port := listen(t, func(conn net.Conn) {
			co := &dns.Conn{Conn: conn}
			q, err := co.ReadMsg()
			if err != nil {
				return
			}
			r := new(dns.Msg)
			r.SetReply(q)
			if c.recursive {
				r.RecursionAvailable = true
				a, _ := dns.NewRR("example.com. 60 IN A 192.0.2.1")
				r.Answer = append(r.Answer, a)
			} else {
				r.Rcode = dns.RcodeRefused
			}
			co.WriteMsg(r)
		})
		dnsPort = port
		fs := Scan(context.Background(), guard(), lo, []int{port}, nil)
		if got := byCheck(fs, "dns.open-resolver") != nil; got != c.want || byCheck(fs, "port.open") == nil {
			t.Errorf("récursif=%v : %+v", c.recursive, fs)
		}
	}
}
