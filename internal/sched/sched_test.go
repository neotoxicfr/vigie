package sched

import (
	"testing"
	"time"
)

func TestDue(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	day := 24 * time.Hour
	cases := []struct {
		last    time.Time
		cadence time.Duration
		want    bool
	}{
		{time.Time{}, day, true},
		{now.Add(-day), day, true},
		{now.Add(-day + time.Minute), day, false},
		{now.Add(-48 * time.Hour), 0, false},
		{time.Time{}, 0, false},
	}
	for i, c := range cases {
		if got := Due(c.last, c.cadence, now); got != c.want {
			t.Errorf("cas %d : %v, attendu %v", i, got, c.want)
		}
	}
}
