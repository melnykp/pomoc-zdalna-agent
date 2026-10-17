package transport

import (
	"testing"
	"time"
)

func TestBackoffWithoutJitterDoubles(t *testing.T) {
	b := Backoff{Min: time.Second, Max: 5 * time.Minute}
	want := []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, w := range want {
		if got := b.Next(i); got != w {
			t.Fatalf("próba %d: %v, oczekiwano %v", i, got, w)
		}
	}
	if got := b.Next(20); got != 5*time.Minute {
		t.Fatalf("po przekroczeniu maksimum powinno być 5m, jest %v", got)
	}
	if got := b.Next(-3); got != time.Second {
		t.Fatalf("ujemna próba powinna dać minimum, jest %v", got)
	}
}

func TestBackoffJitterStaysInBounds(t *testing.T) {
	b := DefaultBackoff()
	for i := 0; i < 1000; i++ {
		d := b.Next(0)
		if d < 800*time.Millisecond || d > 1200*time.Millisecond {
			t.Fatalf("rozrzut poza ±20 %%: %v", d)
		}
		if m := b.Next(30); m > 6*time.Minute || m < 4*time.Minute {
			t.Fatalf("maksimum z rozrzutem poza zakresem: %v", m)
		}
	}
}
