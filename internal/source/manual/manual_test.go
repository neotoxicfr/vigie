package manual

import (
	"context"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/neotoxicfr/vigie/internal/store"
)

func TestValidate(t *testing.T) {
	cases := []struct {
		host      string
		ports     []int
		wantHost  string
		wantPorts []int
		ok        bool
	}{
		{" App.Example.COM. ", []int{443, 80, 443}, "app.example.com", []int{80, 443}, true},
		{"192.0.2.10", nil, "192.0.2.10", nil, true},
		{"[2001:db8::1]", []int{22}, "2001:db8::1", []int{22}, true},
		{"*.example.com", nil, "", nil, false},
		{"-bad.example.com", nil, "", nil, false},
		{"a..example.com", nil, "", nil, false},
		{"exa mple.com", nil, "", nil, false},
		{"example.com/path", nil, "", nil, false},
		{"fe80::1%eth0", nil, "", nil, false},
		{"example.com", []int{0}, "", nil, false},
		{"example.com", []int{70000}, "", nil, false},
		{"", nil, "", nil, false},
	}
	for _, c := range cases {
		h, ps, err := Validate(c.host, c.ports)
		if (err == nil) != c.ok {
			t.Errorf("%q %v : err=%v, ok attendu %v", c.host, c.ports, err, c.ok)
			continue
		}
		if c.ok && (h != c.wantHost || !reflect.DeepEqual(ps, c.wantPorts)) {
			t.Errorf("%q : %q %v, attendu %q %v", c.host, h, ps, c.wantHost, c.wantPorts)
		}
	}
}

func TestAddDiscover(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "v.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st)
	if _, err := m.Add(ctx, "Mail.Example.com", []int{25, 993}, " serveur mail "); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(ctx, "mail.example.com", []int{993, 25}, ""); err == nil {
		t.Error("doublon accepté")
	}
	if _, err := m.Add(ctx, "bad host", nil, ""); err == nil {
		t.Error("hôte invalide enregistré")
	}
	routes, err := m.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 || routes[0].Hosts[0] != "mail.example.com" || !reflect.DeepEqual(routes[0].Ports, []int{25, 993}) || routes[0].Source != "manuel" {
		t.Fatalf("routes : %+v", routes)
	}
	ts, _ := st.Targets(ctx)
	if ts[0].Note != "serveur mail" {
		t.Errorf("note : %q", ts[0].Note)
	}
	st.DeleteTarget(ctx, ts[0].ID)
	if routes, _ := m.Discover(ctx); len(routes) != 0 {
		t.Errorf("cible non supprimée : %+v", routes)
	}
}
