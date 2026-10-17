package releasesig

import (
	"errors"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.2.3", "1.2.3", 0},
		{"1.2.3", "1.2.4", -1},
		{"1.10.0", "1.9.9", 1},
		{"2.0.0", "1.99.99", 1},
		{"0.0.1", "0.0.0", 1},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc1", 1},
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-rc.2", "1.0.0-rc.10", -1},
		{"1.0.0-1", "1.0.0-alpha", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"0.0.1-e2e", "0.0.0-dev", 1},
		{"0.0.2-bad", "0.0.1-e2e", 1},
	}
	for _, c := range cases {
		got, err := CompareVersions(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("%s vs %s: %d err=%v, oczekiwano %d", c.a, c.b, got, err, c.want)
		}
		// Porównanie jest antysymetryczne.
		back, _ := CompareVersions(c.b, c.a)
		if back != -c.want {
			t.Errorf("%s vs %s: odwrotność %d", c.b, c.a, back)
		}
	}
}

func TestCompareVersionsRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "1", "1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.-3", "a.b.c", "1.2.3-", "1.2.3-a..b", "1.2.3+build", "-1.2.3"} {
		if _, err := CompareVersions(bad, "1.0.0"); !errors.Is(err, ErrBadVersion) {
			t.Errorf("%q powinno być odrzucone: %v", bad, err)
		}
		if _, err := CompareVersions("1.0.0", bad); !errors.Is(err, ErrBadVersion) {
			t.Errorf("%q po prawej powinno być odrzucone: %v", bad, err)
		}
	}
}
