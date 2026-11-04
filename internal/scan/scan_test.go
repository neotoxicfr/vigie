package scan

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGuardConcurrencyAndBudget(t *testing.T) {
	g := NewGuard(10, 2, 0)
	var cur, peak atomic.Int32
	var wg sync.WaitGroup
	var budgetErrs atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rel, err := g.Acquire(context.Background(), "h")
			if errors.Is(err, ErrBudget) {
				budgetErrs.Add(1)
				return
			}
			n := cur.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			cur.Add(-1)
			rel()
		}()
	}
	wg.Wait()
	if peak.Load() > 2 {
		t.Errorf("pic de %d connexions simultanées, max 2", peak.Load())
	}
	if budgetErrs.Load() != 2 {
		t.Errorf("%d refus de budget, attendu 2", budgetErrs.Load())
	}
}

func TestGuardDelay(t *testing.T) {
	g := NewGuard(100, 5, 30*time.Millisecond)
	start := time.Now()
	for i := 0; i < 3; i++ {
		rel, err := g.Acquire(context.Background(), "h")
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	if el := time.Since(start); el < 60*time.Millisecond {
		t.Errorf("3 départs en %v, attendu ≥ 60ms", el)
	}
	// Un autre hôte n'attend pas.
	start = time.Now()
	rel, _ := g.Acquire(context.Background(), "autre")
	rel()
	if time.Since(start) > GlobalInterval+20*time.Millisecond { // seul le plafond global peut jouer
		t.Error("le délai d'un hôte freine les autres")
	}
}

func TestGuardSuspend(t *testing.T) {
	g := NewGuard(100, 2, 0)
	g.Suspend("h", "429 Too Many Requests")
	g.Suspend("h", "autre raison")
	if _, err := g.Acquire(context.Background(), "h"); !errors.Is(err, ErrSuspended) {
		t.Fatalf("attendu ErrSuspended, reçu %v", err)
	}
	if s := g.Suspended(); s["h"] != "429 Too Many Requests" {
		t.Errorf("raison : %v", s)
	}
}

func TestDialReleases(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	g := NewGuard(100, 1, 0)
	v := Fixed("origine", netip.MustParseAddr("127.0.0.1"))
	for i := 0; i < 3; i++ { // avec perHost=1, bloquerait si Close ne libérait pas
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		c, err := g.Dial(ctx, v, "app.example.com", port)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		c.Close() // double fermeture sans double libération
	}
	if _, err := g.Dial(context.Background(), Fixed("vide"), "x", port); err == nil {
		t.Error("point de vue sans adresse accepté")
	}
}

func TestGuardGlobalRate(t *testing.T) {
	g := NewGuard(100, 5, 0)
	start := time.Now()
	for i := 0; i < 5; i++ { // 5 hôtes différents : seul le plafond global freine
		rel, err := g.Acquire(context.Background(), string(rune('a'+i)))
		if err != nil {
			t.Fatal(err)
		}
		rel()
	}
	if el := time.Since(start); el < 4*GlobalInterval {
		t.Errorf("5 départs en %v, attendu ≥ %v", el, 4*GlobalInterval)
	}
}
