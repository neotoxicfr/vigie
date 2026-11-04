// Package portscan cherche les ports TCP ouverts d'une adresse parmi une liste
// courte : connexion simple, lecture de la bannière, et pour SSH lecture des
// algorithmes annoncés. Aucune authentification, aucun envoi hors de la version SSH.
package portscan

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/miekg/dns"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

type service struct {
	name string
	sev  check.Severity // Info : simple port.open ; Medium/High : port.risky.<name>
	why  string
}

// services décrit les ports connus ; ceux qui ne s'y trouvent pas restent port.open.
var services = map[int]service{
	21:    {"ftp", check.Medium, "FTP transmet identifiants et données en clair"},
	23:    {"telnet", check.High, "Telnet est en clair et sans contrôle moderne"},
	445:   {"smb", check.High, "SMB ne doit pas être joignable depuis Internet"},
	1433:  {"mssql", check.Medium, "base de données exposée"},
	1883:  {"mqtt", check.Medium, "MQTT sans TLS exposé"},
	2375:  {"docker", check.High, "API Docker sans TLS : prise de contrôle de l'hôte"},
	3306:  {"mysql", check.Medium, "base de données exposée"},
	3389:  {"rdp", check.High, "bureau à distance exposé"},
	5432:  {"postgres", check.Medium, "base de données exposée"},
	5900:  {"vnc", check.High, "VNC exposé, chiffrement et authentification faibles"},
	6379:  {"redis", check.High, "Redis exposé, souvent sans authentification"},
	9200:  {"elasticsearch", check.High, "Elasticsearch exposé, souvent sans authentification"},
	11211: {"memcached", check.High, "Memcached exposé, sans authentification"},
	27017: {"mongodb", check.High, "MongoDB exposé, souvent sans authentification"},
}

// DefaultPorts : accès distants et administration (21-23, 445, 3389, 5900),
// courrier (25, 110, 143, 465, 587, 993, 995), web et services de développement
// (80, 443, 3000, 5000, 8000, 8080, 8443, 8888, 9000, 9090), bases et caches
// (1433, 3306, 5432, 6379, 9200, 11211, 27017), Docker (2375, 2376), MQTT (1883),
// DNS (53) et Plex (32400).
var DefaultPorts = []int{21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
	1433, 1883, 2375, 2376, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443,
	8888, 9000, 9090, 9200, 11211, 27017, 32400}

const (
	dialTimeout   = 3 * time.Second
	bannerTimeout = 2 * time.Second
	maxBanner     = 512
	localNote     = "vu depuis le réseau local, non représentatif de l'extérieur"
)

// Scan teste les ports un à un (le garde borne déjà la cadence) et s'arrête si
// le budget est épuisé ou l'hôte suspendu.
func Scan(ctx context.Context, g *scan.Guard, addr netip.Addr, ports []int, isLocal func(netip.Addr) bool) []check.Finding {
	return ScanFrom(ctx, g, scan.Fixed("dns", addr), addr, ports, isLocal != nil && isLocal(addr))
}

// ScanFrom teste les ports depuis un point de vue donné ; par un proxy, c'est la
// vue de l'extérieur (local vaut alors faux).
func ScanFrom(ctx context.Context, g *scan.Guard, v scan.Vantage, addr netip.Addr, ports []int, local bool) []check.Finding {
	var out []check.Finding
	add := func(f check.Finding) {
		f.Vantage = v.Name
		if local {
			f.Evidence = strings.TrimSpace(f.Evidence + " — " + localNote)
			// Vu seulement du réseau local : l'exposition réelle se lit depuis une
			// sortie externe ; ici ce n'est qu'une information.
			f.Severity = check.Info
		}
		out = append(out, f)
	}
	// Deux ports à la fois : autant que le garde en permet par hôte ; un port
	// filtré coûte tout son délai, en série la durée doublait.
	var mu sync.Mutex
	var stop atomic.Bool
	work := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range work {
				if stop.Load() || ctx.Err() != nil {
					continue
				}
				dctx, cancel := context.WithTimeout(ctx, dialTimeout)
				c, err := g.Dial(dctx, v, addr.String(), p)
				cancel()
				if err != nil {
					if errors.Is(err, scan.ErrBudget) || errors.Is(err, scan.ErrSuspended) {
						stop.Store(true)
					}
					continue
				}
				target := netip.AddrPortFrom(addr, uint16(p)).String()
				fs := probe(c, p, target)
				mu.Lock()
				for _, f := range fs {
					add(f)
				}
				mu.Unlock()
			}
		}()
	}
	for _, p := range ports {
		work <- p
	}
	close(work)
	wg.Wait()
	if local {
		out = append(out, check.Finding{Check: "port.local-vantage", Target: addr.String(), Vantage: v.Name,
			Severity: check.Info, Title: "Ports mesurés depuis le réseau local",
			Evidence: localNote})
	}
	return out
}

func probe(c net.Conn, port int, target string) []check.Finding {
	defer c.Close()
	if port == dnsPort {
		return dnsProbe(c, target)
	}
	_ = c.SetReadDeadline(time.Now().Add(bannerTimeout))
	buf := make([]byte, maxBanner)
	n, _ := c.Read(buf)
	data := buf[:n]
	shown := string(data)
	if strings.HasPrefix(shown, "SSH-") { // la suite est du binaire (KEXINIT)
		shown, _, _ = strings.Cut(shown, "\n")
	}
	banner := clean(shown, 200)

	f := check.Finding{Target: target, Check: "port.open", Severity: check.Info,
		Title: fmt.Sprintf("Port %d ouvert", port)}
	if s, ok := services[port]; ok {
		f.Check = "port.risky." + s.name
		f.Severity = s.sev
		f.Title = fmt.Sprintf("Port %d (%s) ouvert : %s", port, s.name, s.why)
	}
	if banner != "" {
		f.Evidence = "bannière : " + banner
	}
	out := []check.Finding{f}
	if strings.HasPrefix(string(data), "SSH-") {
		out = append(out, sshChecks(c, data, target)...)
	}
	return out
}

// clean retire les caractères de contrôle et borne la longueur (en runes).
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n >= max {
			b.WriteString("…")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) {
			r = ' '
		}
		b.WriteRune(r)
		n++
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func sshChecks(c net.Conn, first []byte, target string) []check.Finding {
	r := io.MultiReader(strings.NewReader(string(first)), c)
	ident, err := readLine(r)
	if err != nil {
		return nil
	}
	out := []check.Finding{{Check: "port.ssh.version", Target: target, Severity: check.Info,
		Title: "Version SSH annoncée", Evidence: clean(ident, 200)}}
	_ = c.SetDeadline(time.Now().Add(bannerTimeout + time.Second))
	if _, err := io.WriteString(c, "SSH-2.0-"+strings.ReplaceAll(scan.UserAgent(), "/", "_")+"\r\n"); err != nil {
		return out
	}
	lists, err := readKexInit(r)
	if err != nil {
		return out
	}
	weak := func(names []string, bad func(string) bool) string {
		var w []string
		seen := map[string]bool{}
		for _, n := range names {
			if bad(n) && !seen[n] {
				seen[n] = true
				w = append(w, n)
			}
		}
		return strings.Join(w, ", ")
	}
	cipher := append(append([]string{}, lists[2]...), lists[3]...)
	mac := append(append([]string{}, lists[4]...), lists[5]...)
	for _, t := range []struct {
		id, title string
		names     []string
		bad       func(string) bool
	}{
		{"port.ssh.weak-kex", "Échange de clés SSH faible", lists[0], func(n string) bool {
			return n == "diffie-hellman-group1-sha1" || n == "diffie-hellman-group14-sha1" || n == "diffie-hellman-group-exchange-sha1"
		}},
		{"port.ssh.weak-hostkey", "Clé d'hôte SSH faible (SHA-1 ou DSA)", lists[1], func(n string) bool {
			return n == "ssh-rsa" || n == "ssh-dss"
		}},
		{"port.ssh.weak-cipher", "Chiffrement SSH faible", cipher, func(n string) bool {
			return strings.HasSuffix(n, "-cbc") || strings.HasPrefix(n, "arcfour") || strings.HasPrefix(n, "3des")
		}},
		{"port.ssh.weak-mac", "Code d'authentification SSH faible", mac, func(n string) bool {
			return strings.HasPrefix(n, "hmac-md5") || strings.HasPrefix(n, "hmac-sha1") || strings.HasPrefix(n, "umac-64")
		}},
	} {
		if w := weak(t.names, t.bad); w != "" {
			out = append(out, check.Finding{Check: t.id, Target: target, Severity: check.Medium,
				Title: t.title, Evidence: clean(w, 250)})
		}
	}
	return out
}

func readLine(r io.Reader) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for len(line) < 255 {
		if _, err := io.ReadFull(r, b); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return strings.TrimRight(string(line), "\r"), nil
		}
		line = append(line, b[0])
	}
	return "", errors.New("identification trop longue")
}

// readKexInit lit le premier paquet SSH (non chiffré) et en extrait les dix
// listes de noms : kex, hostkey, chiffrements c→s/s→c, MAC c→s/s→c, etc.
func readKexInit(r io.Reader) ([][]string, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := int(hdr[0])<<24 | int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	pad := int(hdr[4])
	if size < 2 || size > 35000 || pad >= size {
		return nil, errors.New("paquet SSH invalide")
	}
	body := make([]byte, size-1)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	p := body[:len(body)-pad]
	if len(p) < 17 || p[0] != 20 {
		return nil, errors.New("pas un KEXINIT")
	}
	p = p[17:]
	lists := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if len(p) < 4 {
			return nil, errors.New("KEXINIT tronqué")
		}
		l := int(p[0])<<24 | int(p[1])<<16 | int(p[2])<<8 | int(p[3])
		p = p[4:]
		if l < 0 || l > len(p) {
			return nil, errors.New("KEXINIT tronqué")
		}
		var names []string
		if l > 0 {
			names = strings.Split(string(p[:l]), ",")
		}
		lists = append(lists, names)
		p = p[l:]
	}
	return lists, nil
}

var dnsPort = 53 // variable pour les tests

// dnsProbe pose, sur TCP, une question récursive pour un nom hors de toute zone
// locale : un serveur qui la résout pour n'importe qui est un résolveur ouvert
// (amplification, empoisonnement). Le DNS ne parle pas le premier : pas de bannière.
func dnsProbe(c net.Conn, target string) []check.Finding {
	f := check.Finding{Target: target, Check: "port.open", Severity: check.Info, Title: fmt.Sprintf("Port %d ouvert", dnsPort)}
	_ = c.SetDeadline(time.Now().Add(bannerTimeout))
	co := &dns.Conn{Conn: c}
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.RecursionDesired = true
	if err := co.WriteMsg(m); err != nil {
		return []check.Finding{f}
	}
	r, err := co.ReadMsg()
	if err != nil {
		f.Evidence = "DNS sur TCP : pas de réponse"
		return []check.Finding{f}
	}
	if r.RecursionAvailable && r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
		return []check.Finding{f, {Target: target, Check: "dns.open-resolver", Severity: check.High,
			Title:    "Résolveur DNS ouvert : il résout pour n'importe qui",
			Evidence: "question récursive pour example.com sur TCP : " + strconv.Itoa(len(r.Answer)) + " réponse(s), récursion disponible"}}
	}
	f.Evidence = "DNS sur TCP : récursion refusée (" + dns.RcodeToString[r.Rcode] + ")"
	return []check.Finding{f}
}
