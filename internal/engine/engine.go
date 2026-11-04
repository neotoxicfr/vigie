// Package engine enchaîne un passage : découverte, analyse de la configuration,
// mesures par point de vue, puis enregistrement des constats.
package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/neotoxicfr/vigie/internal/authprov/authelia"
	"github.com/neotoxicfr/vigie/internal/cdnprov"
	"github.com/neotoxicfr/vigie/internal/cdnprov/cloudflare"
	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/dnsscan"
	"github.com/neotoxicfr/vigie/internal/netinfo"
	"github.com/neotoxicfr/vigie/internal/policy"
	"github.com/neotoxicfr/vigie/internal/portscan"
	"github.com/neotoxicfr/vigie/internal/probe"
	"github.com/neotoxicfr/vigie/internal/scan"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
	"github.com/neotoxicfr/vigie/internal/tlsscan"
)

// Les garde-fous (par hôte, par sortie, budget) bornent la pression ; 16 tâches
// recouvrent les attentes réseau des sorties lentes.
const workers = 16

// Engine lance les passages. Les réglages et les sources sont relus à chaque
// passage : une modification dans l'interface vaut pour le suivant.
type Engine struct {
	runtime func() config.Runtime
	sources func(config.Runtime) []source.Source
	st      *store.Store
	base    context.Context // annulé à l'arrêt de vigie

	mu      sync.Mutex
	current int64
	scope   string
	wg      sync.WaitGroup // passage en cours, attendu à l'arrêt

	phase       atomic.Value // string
	done, total atomic.Int64
}

func New(base context.Context, runtime func() config.Runtime, st *store.Store, sources func(config.Runtime) []source.Source) *Engine {
	return &Engine{runtime: runtime, sources: sources, st: st, base: base}
}

// Wait attend la fin du passage en cours, au plus timeout ; faux si le délai expire.
func (e *Engine) Wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

var ErrRunning = errors.New("un passage est déjà en cours")

// Start lance un passage complet en arrière-plan et rend son identifiant.
func (e *Engine) Start() (int64, error) { return e.start("") }

// StartHost re-teste un seul hôte : les autres gardent leurs constats.
func (e *Engine) StartHost(host string) (int64, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return 0, errors.New("hôte vide")
	}
	return e.start(host)
}

func (e *Engine) start(scope string) (int64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.current != 0 {
		return 0, ErrRunning
	}
	id, err := e.st.BeginRun(e.base, time.Now())
	if err != nil {
		return 0, err
	}
	if scope != "" {
		if err := e.st.SetScope(e.base, id, scope); err != nil {
			return 0, err
		}
	}
	e.current, e.scope = id, scope
	e.phase.Store("découverte")
	e.done.Store(0)
	e.total.Store(0)
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			e.current, e.scope = 0, ""
			e.mu.Unlock()
		}()
		status, note := e.run(id, scope)
		// Contexte neuf : l'état final s'écrit même si vigie s'arrête.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := e.st.FinishRun(ctx, id, time.Now(), status, note); err != nil {
			log.Printf("passage %d : %v", id, err)
		}
		log.Printf("passage %d terminé : %s %s", id, status, note)
	}()
	return id, nil
}

func (e *Engine) Current() (int64, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.current, e.current != 0
}

// Progress : état du passage en cours pour l'affichage en direct.
type Progress struct {
	Running     bool   `json:"running"`
	ID          int64  `json:"id"`
	Scope       string `json:"scope,omitempty"`
	Phase       string `json:"phase"`
	Done, Total int64  `json:"-"`
	Percent     int    `json:"percent"`
}

func (e *Engine) Progress() Progress {
	e.mu.Lock()
	p := Progress{Running: e.current != 0, ID: e.current, Scope: e.scope}
	e.mu.Unlock()
	if !p.Running {
		return p
	}
	p.Phase, _ = e.phase.Load().(string)
	p.Done, p.Total = e.done.Load(), e.total.Load()
	if p.Total > 0 {
		p.Percent = int(p.Done * 100 / p.Total)
	}
	return p
}

// RunSync lance un passage et attend sa fin (ligne de commande).
func (e *Engine) RunSync() (int64, error) {
	id, err := e.Start()
	if err != nil {
		return 0, err
	}
	for {
		if cur, running := e.Current(); !running || cur != id {
			return id, nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// target regroupe tout ce qu'on sait d'un hôte:port.
type target struct {
	scan.Target
	privileged bool
	why        string // raison du privilège (liste blanche, dispense d'authentification)
}

func (e *Engine) run(id int64, scope string) (status, note string) {
	r := e.runtime()
	timeout, _ := time.ParseDuration(r.Scan.Timeout)
	ctx, cancel := context.WithTimeout(e.base, timeout)
	defer cancel()
	var notes []string
	partial := false

	// 1. Découverte (re-test : seulement les routes de l'hôte).
	var routes []source.Route
	for _, s := range e.sources(r) {
		rs, err := s.Discover(ctx)
		if err != nil {
			partial = true
			notes = append(notes, err.Error())
			continue
		}
		routes = append(routes, rs...)
	}
	if scope != "" {
		var kept []source.Route
		for _, rt := range routes {
			for _, h := range rt.Hosts {
				if strings.EqualFold(h, scope) {
					kept = append(kept, rt)
					break
				}
			}
		}
		if len(kept) == 0 {
			kept = []source.Route{{Source: "re-test", Name: scope, Hosts: []string{scope}}}
		}
		routes = kept
	}
	if inv, err := json.Marshal(routes); err == nil && scope == "" {
		e.st.SetInventory(ctx, id, inv)
	}
	if len(routes) == 0 {
		return "failed", strings.Join(append(notes, "aucune route à contrôler"), " ; ")
	}

	local, _ := netinfo.LocalPrefixes()
	// Sa propre IP publique, vue de l'intérieur, passe par le routeur (hairpin) :
	// elle peut montrer ses services côté réseau local, donc non représentative.
	isLocal := func(a netip.Addr) bool {
		for _, p := range r.PublicIPs {
			if p.Unmap() == a.Unmap() {
				return true
			}
		}
		return netinfo.IsLocal(a, local)
	}
	hosts := map[string]bool{}
	for _, rt := range routes {
		for _, h := range rt.Hosts {
			if _, err := netip.ParseAddr(h); err != nil {
				hosts[strings.ToLower(h)] = true
			}
		}
	}
	var hostList []string
	for h := range hosts {
		hostList = append(hostList, h)
	}
	sort.Strings(hostList)

	// 2. Fournisseurs (CDN) puis configuration : chaînes et exposition déduite.
	var findings []check.Finding
	var cdnNotes map[string]string
	var cdnGeo map[string]cdnprov.Geo
	var origins []netip.Addr // cibles des enregistrements proxifiés, lues chez le CDN
	if cf := r.CDN.Cloudflare; cf.Enabled {
		e.phase.Store("Cloudflare")
		res, err := cloudflare.New(cf.TokenFile, "").Scan(ctx, hostList)
		if err != nil {
			partial = true
			notes = append(notes, "cloudflare : "+err.Error())
		}
		findings = append(findings, res.Findings...)
		cdnNotes, cdnGeo = res.Notes, res.Geo
		origins = append(origins, res.Origins...)
		// IPv4 d'abord : le point de vue « origine » essaie les adresses dans l'ordre.
		slices.SortStableFunc(origins, func(a, b netip.Addr) int {
			if a.Unmap().Is4() == b.Unmap().Is4() {
				return 0
			}
			if a.Unmap().Is4() {
				return -1
			}
			return 1
		})
	}
	e.phase.Store("configuration")
	// IP réelles des interfaces (pas l'adresse réseau du préfixe) : une allowlist
	// en /32 sur l'IP de vigie doit être vue.
	egress := append(append([]netip.Addr{}, r.PublicIPs...), netinfo.LocalAddrs()...)
	opts := policy.Options{Templates: r.Policy.Templates, RouteTemplates: r.Policy.RouteTemplates,
		Public: r.Policy.Public, Egress: egress, CDNNotes: cdnNotes}
	if p := r.Policy.AutheliaConfig; p != "" {
		a, err := authelia.Load(p)
		if err != nil {
			partial = true
			notes = append(notes, "authelia : "+err.Error())
		} else {
			opts.Auth = a
		}
	}
	findings = append(findings, policy.Analyze(routes, opts)...)

	// 3. Mesures.
	e.phase.Store("mesures")
	targets := buildTargets(routes, opts)
	for i := range targets {
		targets[i].Page = r.Scan.Pages[strings.ToLower(targets[i].Host)]
	}
	pv := newPublicView(r.Scan.Resolver, isLocal)
	tlsCache := tlsscan.NewCache()
	vantages := []scan.Vantage{pv.vantage()}
	if len(origins) > 0 {
		vantages = append(vantages, scan.Fixed("origine", origins...))
	}
	if len(r.Vantages.Internal) > 0 {
		vantages = append(vantages, scan.Fixed("interne", r.Vantages.Internal...))
	}
	g := scan.NewGuard(r.Scan.Budget, scan.DefaultPerHost, scan.DefaultDelay)

	var mu sync.Mutex
	add := func(fs []check.Finding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}
	jobs := make(chan func(), workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				runSafe(j, add)
				e.done.Add(1)
			}
		}()
	}
	submit := func(f func()) {
		e.total.Add(1)
		select {
		case jobs <- f:
		case <-ctx.Done():
			e.done.Add(1)
		}
	}

	// TLS inconnu (cible manuelle, port atypique) : une poignée de main tranche.
	for i := range targets {
		if t := &targets[i]; !t.TLS && t.Port != 80 {
			t.TLS = speaksTLS(ctx, g, vantages[0], t.Host, t.Port)
		}
	}
	// Sorties par proxy : la vue de l'extérieur (HTTP par le CDN s'il y en a un, et
	// ports de l'origine), sans HTTP/3 ni énumération TLS, déjà faits côté public.
	exitViews, exitFs, exitNotes := exits(ctx, g, r, hostList, routes, opts)
	findings = append(findings, exitFs...)
	if len(exitNotes) > 0 {
		partial = true
		notes = append(notes, exitNotes...)
	}
	for _, t := range targets {
		for _, ev := range exitViews {
			t, v := t, ev.v
			submit(func() { add(probe.Check(ctx, g, v, t.Target)) })
		}
		pub, _ := pv.addrs(ctx, t.Host)
		for _, v := range vantages {
			if v.Name == "origine" && sameAddrs(pub, origins) {
				continue // le public voit déjà l'origine : une seule mesure, une seule ligne
			}
			t, v := t, v
			submit(func() { add(probe.Check(ctx, g, v, t.Target)) })
			if t.TLS {
				submit(func() { add(tlsscan.ScanCached(ctx, g, v, t.Host, t.Port, tlsCache)) })
			}
		}
	}
	submit(func() {
		add(dnsscan.Scan(ctx, g, dnsscan.Options{Resolver: r.Scan.Resolver, Origins: origins,
			IsCDN: func(a netip.Addr) bool { _, ok := netinfo.CDN(a); return ok }}, hostList))
	})
	submit(func() { add(parity(ctx, g, pv, targets)) })

	ports := r.Scan.Ports
	if len(ports) == 0 {
		ports = portscan.DefaultPorts
	}
	var portAddrs []netip.Addr
	if scope == "" {
		declared := append(append(append([]netip.Addr{}, origins...), r.Vantages.Internal...), r.PublicIPs...)
		portAddrs = portTargets(ctx, declared, hostList, isLocal)
	}
	for _, a := range portAddrs {
		a := a
		submit(func() { add(portscan.Scan(ctx, g, a, ports, isLocal)) })
	}
	if scope == "" && len(exitViews) > 0 {
		if len(origins) > 0 {
			submit(func() { add(originBypass(ctx, g, exitViews, hostList, origins)) })
		}
	}
	if scope == "" {
		seenA := map[netip.Addr]bool{}
		for _, a := range append(append([]netip.Addr{}, origins...), r.PublicIPs...) {
			if seenA[a] {
				continue
			}
			seenA[a] = true
			for _, ev := range exitViews {
				if a.Unmap().Is6() && ev.ip.IsValid() && !ev.ip6.IsValid() {
					continue // sortie connue sans IPv6 : un échec ne dirait rien des ports
				}
				a, v := a, ev.v
				submit(func() { add(portscan.ScanFrom(ctx, g, v, a, ports, false)) })
			}
		}
	}
	close(jobs)
	wg.Wait()
	e.phase.Store("enregistrement")
	if scope == "" {
		findings = internalRoutes(findings, routes, exitViews, ports)
	}

	// DNS divisé : la mesure « public » a suivi la réponse publique.
	for h, loc := range pv.splitHosts() {
		var ls []string
		for _, a := range loc {
			ls = append(ls, a.String())
		}
		findings = append(findings, check.Finding{Check: "dns.private-answer", Target: h, Vantage: "dns", Severity: check.Info,
			Title:    "DNS divisé : la mesure publique suit la réponse d'un résolveur public",
			Evidence: "le DNS local répond " + strings.Join(ls, ", ")})
	}

	findings = classifyGeo(findings, exitViews, cdnGeo)
	findings = judgeExposure(findings, exitViews, hostExposure(routes, opts))

	// Exclusions : contrôles assumés partout, plus enregistrés.
	if len(r.Exclusions) > 0 {
		ex := map[string]bool{}
		for _, x := range r.Exclusions {
			ex[x] = true
		}
		kept := findings[:0]
		for _, f := range findings {
			if !ex[f.Check] {
				kept = append(kept, f)
			}
		}
		findings = kept
	}

	// Point de vue privilégié : seules les mesures qui traversent le proxy (HTTP,
	// TLS, parité) passent ses allowlists.
	priv := map[string]bool{}
	reasons := map[string]bool{}
	for _, t := range targets {
		if t.privileged {
			priv[strings.ToLower(t.Host)] = true
			reasons[t.why] = true
		}
	}
	if len(priv) > 0 && scope == "" {
		// Dispense configurée exprès (LAN, IP de l'administrateur) : la dire une fois,
		// comme une limite de mesure et jamais comme un écart.
		var hs, rs []string
		for h := range priv {
			hs = append(hs, h)
		}
		for w := range reasons {
			rs = append(rs, w)
		}
		sort.Strings(hs)
		sort.Strings(rs)
		findings = append(findings, check.Finding{Check: "access.privileged", Target: "vigie", Vantage: "config", Severity: check.Info,
			Title:    fmt.Sprintf("Points de vue directs en liste blanche ou dispensés d'authentification : %d hôtes (configuration voulue)", len(hs)),
			Evidence: trim(strings.Join(rs, " ; ") + " — hôtes : " + strings.Join(hs, ", "))})
	}
	exitPriv := map[string]map[string]bool{}
	for _, ev := range exitViews {
		exitPriv[ev.v.Name] = ev.priv
	}
	for i := range findings {
		f := &findings[i]
		// Ports vus d'une sortie dont l'IP est en liste blanche ailleurs : le pare-feu
		// de l'hôte peut lui aussi la laisser passer, la mesure n'est pas celle d'un inconnu.
		if m, isExit := exitPriv[f.Vantage]; isExit && strings.HasPrefix(f.Check, "port.") && len(m) > 0 {
			// Sortie de confiance : le pare-feu de l'hôte peut la laisser passer ; ce
			// n'est pas l'exposition à Internet, donc une information (comme le LAN).
			f.Privileged = true
			if f.Severity > check.Info {
				f.Evidence = trim(f.Evidence + " — vu d'une sortie en liste blanche, non représentatif d'un inconnu")
				f.Severity = check.Info
			}
			continue
		}
		if !strings.HasPrefix(f.Check, "http.") && !strings.HasPrefix(f.Check, "tls.") && !strings.HasPrefix(f.Check, "parity.") {
			continue
		}
		if m, isExit := exitPriv[f.Vantage]; isExit {
			f.Privileged = m[check.Unit(f.Target)]
		} else if f.Vantage != "inconnu" && f.Vantage != "config" && priv[check.Unit(f.Target)] {
			f.Privileged = true
		}
	}

	if err := e.st.SaveFindings(context.Background(), id, findings); err != nil {
		return "failed", err.Error()
	}
	units := measuredUnits(routes, targets, hostList, portAddrs, findings, g)
	if err := e.st.SetMeasured(context.Background(), id, units); err != nil {
		return "failed", err.Error()
	}
	if s := g.Suspended(); len(s) > 0 {
		partial = true
		var hs []string
		for h, why := range s {
			hs = append(hs, h+" ("+why+")")
		}
		sort.Strings(hs)
		notes = append(notes, "hôtes suspendus : "+strings.Join(hs, ", "))
	}
	for _, f := range findings {
		if f.Check == "scan.panic" {
			partial = true
			notes = append(notes, "un contrôle a planté")
			break
		}
	}
	if g.Exhausted() {
		partial = true
		notes = append(notes, "budget de requêtes épuisé : passage incomplet")
	}
	if ctx.Err() != nil {
		partial = true
		notes = append(notes, "durée maximale atteinte ou arrêt de vigie")
	}
	if partial {
		return "partial", strings.Join(notes, " ; ")
	}
	return "ok", ""
}

// buildTargets fusionne les routes par hôte:port ; un hôte est privilégié si
// une de ses routes l'est.
func buildTargets(routes []source.Route, o policy.Options) []target {
	by := map[string]*target{}
	var order []string
	for _, r := range routes {
		priv, why := policy.Privileged(r, o)
		ports := r.Ports
		if len(ports) == 0 {
			ports = []int{443, 80}
		}
		for _, h := range r.Hosts {
			for _, p := range ports {
				k := net.JoinHostPort(h, strconv.Itoa(p))
				t := by[k]
				if t == nil {
					t = &target{Target: scan.Target{Host: h, Port: p, TLS: r.TLS && p != 80 || p == 443 || p == 8443}}
					by[k] = t
					order = append(order, k)
				}
				if t.Route == nil {
					rc := r
					t.Route = &rc
				}
				t.Paths = appendUnique(t.Paths, r.Paths...)
				t.privileged = t.privileged || priv
				if priv && t.why == "" {
					t.why = why
				}
			}
		}
	}
	out := make([]target, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

func speaksTLS(ctx context.Context, g *scan.Guard, v scan.Vantage, host string, port int) bool {
	c, err := g.Dial(ctx, v, host, port)
	if err != nil {
		return false
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	cfg := &tls.Config{InsecureSkipVerify: true} // on teste le protocole, pas le certificat
	if _, err := netip.ParseAddr(host); err != nil {
		cfg.ServerName = host
	}
	return tls.Client(c, cfg).HandshakeContext(ctx) == nil
}

func appendUnique(dst []string, vs ...string) []string {
	for _, v := range vs {
		found := false
		for _, d := range dst {
			found = found || d == v
		}
		if !found {
			dst = append(dst, v)
		}
	}
	return dst
}

// portTargets : adresses déclarées (origine, interne, IP publiques), plus les
// adresses LOCALES des hôtes. Jamais une adresse publique non déclarée : un DNS
// pendant ou un hôte chez un tiers ne doit pas valoir un scan de ports chez lui.
func portTargets(ctx context.Context, declared []netip.Addr, hosts []string, isLocal func(netip.Addr) bool) []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	push := func(a netip.Addr) {
		a = a.Unmap()
		if !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	for _, a := range declared {
		push(a)
	}
	for _, h := range hosts {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if isLocal(a.Unmap()) {
				push(a)
			}
		}
	}
	return out
}

// measuredUnits liste ce que le passage a réellement mesuré (check.Unit) : un
// hôte suspendu (429) n'en fait pas partie ; budget épuisé, seules comptent les
// unités qui ont produit un constat.
func measuredUnits(routes []source.Route, targets []target, hosts []string, ports []netip.Addr, fs []check.Finding, g *scan.Guard) []string {
	set := map[string]bool{}
	for _, f := range fs {
		set[check.Unit(f.Target)] = true
	}
	if !g.Exhausted() {
		for _, r := range routes {
			set[strings.ToLower(r.Name)] = true
		}
		for _, t := range targets {
			set[strings.ToLower(t.Host)] = true
		}
		for _, h := range hosts {
			set[strings.ToLower(h)] = true
			if apex, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
				set[apex] = true
			}
		}
		for _, a := range ports {
			set[a.String()] = true
		}
		set["ipv4"], set["ipv6"] = true, true
	}
	for h := range g.Suspended() {
		delete(set, strings.ToLower(h))
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// runSafe protège le passage d'une panique d'une bibliothèque face à une réponse
// hostile : le contrôle concerné est perdu, pas vigie.
func runSafe(job func(), add func([]check.Finding)) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("panique dans un contrôle : %v", r)
			add([]check.Finding{{Check: "scan.panic", Target: "vigie", Vantage: "config", Severity: check.Low,
				Title: "Un contrôle a planté : résultat incomplet", Evidence: trim(fmt.Sprint(r))}})
		}
	}()
	job()
}

func (t target) String() string { return fmt.Sprint(t.Target) }

// internalRoutes : une route servie seulement sur des ports explorés qu'aucune
// sortie inconnue ne voit ouverts tient à un point d'entrée interne (API ou tableau
// de bord du proxy) ; ses défauts de chaîne ne sont pas exposés, ils passent en info.
func internalRoutes(fs []check.Finding, routes []source.Route, views []exitView, scanned []int) []check.Finding {
	strangers := map[string]bool{}
	for _, ev := range views {
		if len(ev.priv) == 0 && ev.ip.IsValid() {
			strangers[ev.v.Name] = true
		}
	}
	if len(strangers) == 0 {
		return fs // aucune vue de l'extérieur : on ne sait pas
	}
	open := map[int]bool{}
	for _, f := range fs {
		if strangers[f.Vantage] && strings.HasPrefix(f.Check, "port.") {
			if ap, err := netip.ParseAddrPort(f.Target); err == nil {
				open[int(ap.Port())] = true
			}
		}
	}
	internal := map[string][]int{}
	for _, rt := range routes {
		if len(rt.Ports) > 0 && !slices.ContainsFunc(rt.Ports, func(p int) bool { return open[p] || !slices.Contains(scanned, p) }) {
			internal[rt.Name] = rt.Ports
		}
	}
	for i := range fs {
		f := &fs[i]
		if ps, ok := internal[f.Target]; ok && f.Check == "chain.problem" && f.Severity > check.Info {
			f.Severity = check.Info
			f.Evidence = trim(fmt.Sprintf("%s — route servie seulement sur le port %v, fermé depuis les sorties inconnues : point d'entrée interne", f.Evidence, ps))
		}
	}
	return fs
}
