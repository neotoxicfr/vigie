// Package npm découvre les hôtes d'un Nginx Proxy Manager en lisant sa base
// SQLite en lecture seule. MySQL/MariaDB n'est pas pris en charge.
package npm

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/neotoxicfr/vigie/internal/source"
	_ "modernc.org/sqlite" // driver "sqlite"
)

type NPM struct{ name, path string }

func New(name, dbPath string) *NPM { return &NPM{name, dbPath} }

func (n *NPM) Name() string { return "npm/" + n.name }

var sqliteMagic = []byte("SQLite format 3\x00")

func (n *NPM) Discover(ctx context.Context) ([]source.Route, error) {
	rs, err := n.discover(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", n.Name(), err)
	}
	return rs, nil
}

func (n *NPM) discover(ctx context.Context) ([]source.Route, error) {
	f, err := os.Open(n.path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, len(sqliteMagic))
	_, err = f.Read(head)
	f.Close()
	if err != nil || !bytes.Equal(head, sqliteMagic) {
		return nil, fmt.Errorf("%s n'est pas une base SQLite (seul SQLite est pris en charge, pas MySQL/MariaDB)", n.path)
	}
	// immutable=1 : aucune écriture, aucun fichier -wal/-shm créé ; query_only en garde-fou.
	esc := strings.NewReplacer("%", "%25", "?", "%3f", "#", "%23").Replace(n.path)
	db, err := sql.Open("sqlite", "file:"+esc+"?mode=ro&immutable=1&_pragma=query_only(1)")
	if err != nil {
		return nil, err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	q := &querier{ctx: ctx, db: db, cols: map[string]map[string]bool{}}
	if err := q.schema(); err != nil {
		return nil, err
	}
	if !q.has("proxy_host") {
		return nil, fmt.Errorf("pas de table proxy_host : ce n'est pas une base Nginx Proxy Manager")
	}
	acl, err := q.accessLists()
	if err != nil {
		return nil, err
	}
	var out []source.Route
	for _, f := range []func(*querier, map[int64]*accessList, string) ([]source.Route, error){proxyHosts, redirections, deadHosts, streams} {
		rs, err := f(q, acl, n.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, rs...)
	}
	return out, nil
}

type querier struct {
	ctx  context.Context
	db   *sql.DB
	cols map[string]map[string]bool
}

func (q *querier) schema() error {
	rows, err := q.db.QueryContext(q.ctx, `SELECT m.name, p.name FROM sqlite_master m, pragma_table_info(m.name) p WHERE m.type = 'table'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var t, c string
		if err := rows.Scan(&t, &c); err != nil {
			return err
		}
		if q.cols[t] == nil {
			q.cols[t] = map[string]bool{}
		}
		q.cols[t][c] = true
	}
	return rows.Err()
}

func (q *querier) has(t string) bool { return q.cols[t] != nil }

// row : valeurs d'une ligne par nom de colonne ; les colonnes absentes du
// schéma (versions anciennes) valent NULL.
type row map[string]any

func (r row) str(k string) string {
	switch v := r[k].(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case int64:
		return strconv.FormatInt(v, 10)
	}
	return ""
}

func (r row) num(k string) int64 {
	switch v := r[k].(type) {
	case int64:
		return v
	case float64:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	case []byte:
		n, _ := strconv.ParseInt(string(v), 10, 64)
		return n
	}
	return 0
}

// query lit les colonnes demandées (celles qui existent) de table, lignes
// non supprimées et activées si les colonnes existent, triées par id.
func (q *querier) query(table string, cols ...string) ([]row, error) {
	if !q.has(table) {
		return nil, nil
	}
	var sel []string
	for _, c := range cols {
		if q.cols[table][c] {
			sel = append(sel, c)
		}
	}
	stmt := "SELECT " + strings.Join(sel, ", ") + " FROM " + table
	var where []string
	if q.cols[table]["is_deleted"] {
		where = append(where, "is_deleted = 0")
	}
	if len(where) > 0 {
		stmt += " WHERE " + strings.Join(where, " AND ")
	}
	if q.cols[table]["id"] {
		stmt += " ORDER BY id"
	}
	rows, err := q.db.QueryContext(q.ctx, stmt)
	if err != nil {
		return nil, fmt.Errorf("lecture de %s : %w", table, err)
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		vals := make([]any, len(sel))
		ptrs := make([]any, len(sel))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := row{}
		for i, c := range sel {
			r[c] = vals[i]
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type client struct {
	allow bool
	pfx   []netip.Prefix
	raw   string
}

type accessList struct {
	name       string
	satisfyAny bool
	passAuth   bool
	clients    []client
	auths      int
}

func (q *querier) accessLists() (map[int64]*accessList, error) {
	out := map[int64]*accessList{}
	ls, err := q.query("access_list", "id", "name", "is_deleted", "satisfy_any", "satify_any", "pass_auth")
	if err != nil {
		return nil, err
	}
	for _, r := range ls {
		a := &accessList{name: r.str("name"), satisfyAny: r.num("satisfy_any")+r.num("satify_any") > 0, passAuth: true}
		if _, ok := r["pass_auth"]; ok {
			a.passAuth = r.num("pass_auth") != 0
		}
		out[r.num("id")] = a
	}
	cs, err := q.query("access_list_client", "access_list_id", "address", "directive", "id")
	if err != nil {
		return nil, err
	}
	for _, r := range cs {
		if a := out[r.num("access_list_id")]; a != nil {
			a.clients = append(a.clients, client{r.str("directive") == "allow", parseAddr(r.str("address")), r.str("address")})
		}
	}
	// Seule la présence d'identifiants compte : ni nom ni mot de passe ne sont lus.
	us, err := q.query("access_list_auth", "access_list_id")
	if err != nil {
		return nil, err
	}
	for _, r := range us {
		if a := out[r.num("access_list_id")]; a != nil {
			a.auths++
		}
	}
	return out, nil
}

func parseAddr(s string) []netip.Prefix {
	s = strings.TrimSpace(s)
	if s == "all" {
		return []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	}
	if strings.Contains(s, "/") {
		if p, err := netip.ParsePrefix(s); err == nil {
			return []netip.Prefix{p.Masked()}
		}
		return nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}
	}
	return nil
}

const maxAllowed = 4096

// allowed : NPM écrit les règles dans l'ordre puis « deny all » ; la première
// qui correspond gagne. On en déduit les adresses autorisées.
func (a *accessList) allowed() ([]netip.Prefix, bool) {
	rem := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	var acc []netip.Prefix
	for _, c := range a.clients {
		for _, p := range c.pfx {
			var next []netip.Prefix
			for _, r := range rem {
				if c.allow && r.Addr().Is4() == p.Addr().Is4() && r.Overlaps(p) {
					if r.Bits() > p.Bits() {
						acc = append(acc, r)
					} else {
						acc = append(acc, p)
					}
				}
				next = append(next, subtract(r, p)...)
			}
			if rem = next; len(rem)+len(acc) > maxAllowed {
				return nil, false
			}
		}
	}
	return acc, true
}

func subtract(c, d netip.Prefix) []netip.Prefix {
	if c.Addr().Is4() != d.Addr().Is4() || !c.Overlaps(d) {
		return []netip.Prefix{c}
	}
	if d.Bits() <= c.Bits() {
		return nil
	}
	lo := netip.PrefixFrom(c.Addr(), c.Bits()+1)
	b := c.Addr().AsSlice()
	b[c.Bits()/8] |= 0x80 >> (c.Bits() % 8)
	a, _ := netip.AddrFromSlice(b)
	return append(subtract(lo, d), subtract(netip.PrefixFrom(a, c.Bits()+1), d)...)
}

func raw(v any) json.RawMessage { b, _ := json.Marshal(v); return b }

// hosts lit domain_names (tableau JSON) ; jokers et expressions vont en problèmes.
func hosts(r row) (hs, probs []string) {
	var names []string
	if err := json.Unmarshal([]byte(r.str("domain_names")), &names); err != nil {
		return nil, []string{"domain_names illisible"}
	}
	for _, h := range names {
		h = strings.ToLower(strings.TrimSpace(h))
		if strings.ContainsAny(h, "*~") {
			probs = append(probs, "domaine non littéral ignoré : "+h)
		} else if h != "" && !slices.Contains(hs, h) {
			hs = append(hs, h)
		}
	}
	if len(hs) == 0 {
		probs = append(probs, "aucun domaine littéral : hôtes non scannables")
	}
	return
}

func label(r row, kind string) string {
	var names []string
	json.Unmarshal([]byte(r.str("domain_names")), &names)
	first := "?"
	if len(names) > 0 {
		first = names[0]
	}
	return fmt.Sprintf("%s (%s %d)", first, kind, r.num("id"))
}

// common pose ports, TLS, HSTS, redirection HTTPS et config avancée, communs
// aux trois types d'hôtes web.
func common(r row, rt *source.Route) {
	tls := r.num("certificate_id") > 0
	rt.TLS = tls
	rt.Ports = []int{80}
	if tls {
		rt.Ports = []int{80, 443}
	}
	if tls && r.num("ssl_forced") > 0 {
		rt.Declared = append(rt.Declared, "ssl_forced")
		rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "ssl_forced", Type: "ssl_forced", Kind: source.Redirect,
			Config: raw(map[string]any{"code": 301, "target": "https"})})
	}
	if tls && r.num("hsts_enabled") > 0 {
		v := "max-age=63072000"
		if r.num("hsts_subdomains") > 0 {
			v += "; includeSubDomains"
		}
		rt.Declared = append(rt.Declared, "hsts")
		rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "hsts", Type: "hsts", Kind: source.Headers,
			Config: raw(map[string]string{"Strict-Transport-Security": v})})
	}
	if strings.TrimSpace(r.str("advanced_config")) != "" {
		rt.Problems = append(rt.Problems, "config avancée non analysée")
	}
}

func proxyHosts(q *querier, acl map[int64]*accessList, src string) ([]source.Route, error) {
	rows, err := q.query("proxy_host", "id", "domain_names", "forward_scheme", "forward_host", "forward_ip", "forward_port",
		"access_list_id", "certificate_id", "ssl_forced", "hsts_enabled", "hsts_subdomains", "enabled", "advanced_config", "locations")
	if err != nil {
		return nil, err
	}
	var out []source.Route
	for _, r := range rows {
		if _, ok := r["enabled"]; ok && r.num("enabled") == 0 {
			continue
		}
		rt := source.Route{Source: src, Name: label(r, "proxy_host")}
		rt.Hosts, rt.Problems = hosts(r)
		common(r, &rt)
		scheme := r.str("forward_scheme")
		if scheme == "" {
			scheme = "http"
		}
		host := r.str("forward_host") + r.str("forward_ip")
		rt.Backends = []string{fmt.Sprintf("%s://%s:%d", scheme, host, r.num("forward_port"))}
		var locs []struct {
			Path   string `json:"path"`
			Scheme string `json:"forward_scheme"`
			Host   string `json:"forward_host"`
			Port   int    `json:"forward_port"`
		}
		if json.Unmarshal([]byte(r.str("locations")), &locs) == nil && len(locs) > 0 {
			for _, l := range locs {
				rt.Backends = append(rt.Backends, fmt.Sprintf("%s://%s:%d", l.Scheme, l.Host, l.Port))
			}
			rt.Problems = append(rt.Problems, fmt.Sprintf("%d emplacement(s) personnalisé(s) : accès propre non analysé", len(locs)))
		}
		if id := r.num("access_list_id"); id > 0 {
			if a := acl[id]; a != nil {
				applyACL(&rt, a)
			} else {
				rt.Problems = append(rt.Problems, fmt.Sprintf("liste d'accès %d introuvable ou supprimée", id))
			}
		}
		out = append(out, rt)
	}
	return out, nil
}

func applyACL(rt *source.Route, a *accessList) {
	satisfy := "all"
	if a.satisfyAny {
		satisfy = "any"
	}
	if len(a.clients) > 0 {
		rt.Declared = append(rt.Declared, "access_list/clients")
		var rules []string
		for _, c := range a.clients {
			v := "deny"
			if c.allow {
				v = "allow"
			}
			rules = append(rules, v+" "+c.raw)
		}
		cfg := raw(map[string]any{"access_list": a.name, "rules": rules, "satisfy": satisfy})
		if list, ok := a.allowed(); ok {
			rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "access_list", Type: "access_list_client", Kind: source.IPAllow, AllowFrom: list, Config: cfg})
		} else {
			rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "access_list", Type: "access_list_client", Kind: source.Other, Config: cfg})
			rt.Problems = append(rt.Problems, "liste de clients trop fragmentée pour en déduire les adresses autorisées")
		}
	}
	if a.auths > 0 {
		rt.Declared = append(rt.Declared, "access_list/auth")
		rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "access_list", Type: "access_list_auth", Kind: source.BasicAuth,
			Config: raw(map[string]any{"access_list": a.name, "users": a.auths, "satisfy": satisfy, "pass_auth": a.passAuth})})
	}
	if a.satisfyAny && len(a.clients) > 0 && a.auths > 0 {
		for i := range rt.Middlewares {
			if rt.Middlewares[i].Type == "access_list_client" && rt.Middlewares[i].Kind == source.IPAllow {
				rt.Middlewares[i].OrAuth = true
			}
		}
		rt.Problems = append(rt.Problems, "satisfy any : l'adresse OU l'authentification suffit")
	}
}

func redirections(q *querier, _ map[int64]*accessList, src string) ([]source.Route, error) {
	rows, err := q.query("redirection_host", "id", "domain_names", "forward_scheme", "forward_domain_name", "forward_http_code",
		"preserve_path", "certificate_id", "ssl_forced", "hsts_enabled", "hsts_subdomains", "enabled", "advanced_config")
	if err != nil {
		return nil, err
	}
	var out []source.Route
	for _, r := range rows {
		if _, ok := r["enabled"]; ok && r.num("enabled") == 0 {
			continue
		}
		rt := source.Route{Source: src, Name: label(r, "redirection_host")}
		rt.Hosts, rt.Problems = hosts(r)
		common(r, &rt)
		code := r.num("forward_http_code")
		if code == 0 {
			code = 302
		}
		rt.Declared = append(rt.Declared, "redirect")
		rt.Middlewares = append(rt.Middlewares, source.Middleware{Name: "redirect", Type: "redirection_host", Kind: source.Redirect,
			Config: raw(map[string]any{"code": code, "scheme": r.str("forward_scheme"), "domain": r.str("forward_domain_name"), "preserve_path": r.num("preserve_path") > 0})})
		out = append(out, rt)
	}
	return out, nil
}

func deadHosts(q *querier, _ map[int64]*accessList, src string) ([]source.Route, error) {
	rows, err := q.query("dead_host", "id", "domain_names", "certificate_id", "ssl_forced", "hsts_enabled", "hsts_subdomains", "enabled", "advanced_config")
	if err != nil {
		return nil, err
	}
	var out []source.Route
	for _, r := range rows {
		if _, ok := r["enabled"]; ok && r.num("enabled") == 0 {
			continue
		}
		rt := source.Route{Source: src, Name: label(r, "dead_host"), Rule: "404"}
		rt.Hosts, rt.Problems = hosts(r)
		common(r, &rt)
		out = append(out, rt)
	}
	return out, nil
}

func streams(q *querier, _ map[int64]*accessList, src string) ([]source.Route, error) {
	rows, err := q.query("stream", "id", "incoming_port", "forwarding_host", "forward_ip", "forwarding_port", "tcp_forwarding", "udp_forwarding", "certificate_id", "enabled")
	if err != nil {
		return nil, err
	}
	var out []source.Route
	for _, r := range rows {
		if _, ok := r["enabled"]; ok && r.num("enabled") == 0 {
			continue
		}
		port := int(r.num("incoming_port"))
		rt := source.Route{Source: src, Name: fmt.Sprintf("stream %d (stream %d)", port, r.num("id")), Ports: []int{port}, TLS: r.num("certificate_id") > 0}
		to := fmt.Sprintf("%s%s:%d", r.str("forwarding_host"), r.str("forward_ip"), r.num("forwarding_port"))
		var protos []string
		if r.num("tcp_forwarding") > 0 {
			protos = append(protos, "tcp")
		}
		if r.num("udp_forwarding") > 0 {
			protos = append(protos, "udp")
		}
		for _, p := range protos {
			rt.Backends = append(rt.Backends, p+"://"+to)
		}
		rt.Rule = strings.Join(protos, "+")
		out = append(out, rt)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Ports[0] < out[j].Ports[0] })
	return out, nil
}
