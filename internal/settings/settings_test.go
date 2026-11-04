package settings

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/store"
)

func TestLoadSave(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seed := config.DefaultRuntime()
	seed.PublicIPs = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	r, err := Load(ctx, st, seed)
	if err != nil || len(r.PublicIPs) != 1 {
		t.Fatalf("amorçage : %+v %v", r, err)
	}
	r.Exclusions = []string{"http.csp.no-script-src"}
	if err := Save(ctx, st, r); err != nil {
		t.Fatal(err)
	}
	// Le fichier ne réécrit plus les réglages une fois en base.
	got, _ := Load(ctx, st, config.DefaultRuntime())
	if len(got.Exclusions) != 1 || len(got.PublicIPs) != 1 {
		t.Errorf("relu : %+v", got)
	}
	bad := got
	bad.Scan.Budget = 0
	if err := Save(ctx, st, bad); err == nil {
		t.Error("réglage invalide enregistré")
	}
	if again, _ := Load(ctx, st, config.DefaultRuntime()); again.Scan.Budget != 20000 {
		t.Errorf("la base a pris un réglage invalide : %d", again.Scan.Budget)
	}
}
