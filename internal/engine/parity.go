package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/scan"
)

// En-têtes dont la présence doit être la même en IPv4 et en IPv6.
var parityHeaders = []string{"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
	"X-Content-Type-Options", "Referrer-Policy", "Server"}

type snapshot struct {
	status  int
	headers []string
	err     error
}

// parity compare, pour chaque hôte HTTPS joignable en v4 et en v6, le statut de
// « / » et la présence des en-têtes de sécurité : un proxy configuré pour une
// seule famille laisse souvent l'autre nue.
func parity(ctx context.Context, g *scan.Guard, pv *publicView, targets []target) []check.Finding {
	var out []check.Finding
	done := map[string]bool{}
	noRoute := map[string]bool{} // famille sans route depuis la machine de vigie : rien à comparer
	for _, t := range targets {
		if !t.TLS || done[t.Host] {
			continue
		}
		done[t.Host] = true
		if _, err := netip.ParseAddr(t.Host); err == nil {
			continue
		}
		addrs, err := pv.addrs(ctx, t.Host) // comme un visiteur, DNS divisé compris
		if err != nil {
			continue
		}
		var v4, v6 []netip.Addr
		for _, a := range addrs {
			if a.Unmap().Is4() {
				v4 = append(v4, a.Unmap())
			} else {
				v6 = append(v6, a)
			}
		}
		if len(v4) == 0 || len(v6) == 0 {
			continue
		}
		if noRoute["IPv4"] || noRoute["IPv6"] {
			continue
		}
		a := fetch(ctx, g, scan.Fixed("public", v4...), t.Host, t.Port)
		b := fetch(ctx, g, scan.Fixed("public", v6...), t.Host, t.Port)
		// Un seul échec d'un côté peut être passager (délai) : on réessaie une fois
		// cette famille avant de conclure qu'elle est cassée.
		if a.err != nil && b.err == nil {
			a = fetch(ctx, g, scan.Fixed("public", v4...), t.Host, t.Port)
		} else if b.err != nil && a.err == nil {
			b = fetch(ctx, g, scan.Fixed("public", v6...), t.Host, t.Port)
		}
		target := t.Target.String()
		for fam, e := range map[string]error{"IPv4": a.err, "IPv6": b.err} {
			if errors.Is(e, syscall.ENETUNREACH) {
				noRoute[fam] = true
				out = append(out, check.Finding{Check: "parity.no-route", Target: fam, Vantage: "public", Severity: check.Info,
					Title: "Pas de route " + fam + " depuis vigie : parité IPv4/IPv6 non vérifiée", Evidence: trim(e.Error())})
			}
		}
		if noRoute["IPv4"] || noRoute["IPv6"] {
			continue
		}
		switch {
		case a.err != nil && b.err != nil:
			continue
		case (a.err == nil) != (b.err == nil):
			ok, ko, why, addrs := "IPv4", "IPv6", b.err, v6
			if a.err != nil {
				ok, ko, why, addrs = "IPv6", "IPv4", a.err, v4
			}
			out = append(out, check.Finding{Check: "parity.v4v6.unreachable", Target: target, Vantage: "public", Severity: check.Medium,
				Title: fmt.Sprintf("Joignable en %s mais pas en %s", ok, ko), Evidence: trim(fmt.Sprintf("%s %v, deux essais : %v", ko, addrs, why))})
		case a.status != b.status || strings.Join(a.headers, ",") != strings.Join(b.headers, ","):
			out = append(out, check.Finding{Check: "parity.v4v6", Target: target, Vantage: "public", Severity: check.Medium,
				Title:    "Réponses différentes en IPv4 et en IPv6",
				Evidence: trim(fmt.Sprintf("IPv4 : %d [%s] ; IPv6 : %d [%s]", a.status, strings.Join(a.headers, ", "), b.status, strings.Join(b.headers, ", ")))})
		}
	}
	return out
}

func fetch(ctx context.Context, g *scan.Guard, v scan.Vantage, host string, port int) snapshot {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return g.Dial(ctx, v, host, port) },
		// La validité du certificat relève de tlsscan ; ici on ne compare que les réponses.
		TLSClientConfig:   &tls.Config{ServerName: host, InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+net.JoinHostPort(host, fmt.Sprint(port))+"/", nil)
	if err != nil {
		return snapshot{err: err}
	}
	req.Header.Set("User-Agent", scan.UserAgent())
	resp, err := c.Do(req)
	if err != nil {
		return snapshot{err: err}
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		g.Suspend(host, "429 Too Many Requests")
	}
	s := snapshot{status: resp.StatusCode}
	for _, h := range parityHeaders {
		if resp.Header.Get(h) != "" {
			s.headers = append(s.headers, h)
		}
	}
	sort.Strings(s.headers)
	return s
}

func trim(s string) string {
	if r := []rune(s); len(r) > 300 {
		return string(r[:299]) + "…"
	}
	return s
}
