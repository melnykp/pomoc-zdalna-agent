package peer

import (
	"testing"
	"time"
)

func TestRateLimiterAllowsFirstThenOncePerInterval(t *testing.T) {
	now := time.Unix(1000, 0)
	r := newRateLimiter(time.Second)
	r.now = func() time.Time { return now }
	if ok, sup := r.allow(); !ok || sup != 0 {
		t.Fatalf("pierwsze zdarzenie: ok=%v pominięte=%d", ok, sup)
	}
	for i := 0; i < 5; i++ {
		now = now.Add(100 * time.Millisecond)
		if ok, _ := r.allow(); ok {
			t.Fatalf("zdarzenie %d w tej samej sekundzie nie powinno przejść", i)
		}
	}
	now = now.Add(time.Second)
	if ok, sup := r.allow(); !ok || sup != 5 {
		t.Fatalf("po sekundzie: ok=%v pominięte=%d (oczekiwano 5)", ok, sup)
	}
	if ok, sup := r.allow(); ok || sup != 0 {
		t.Fatalf("następne od razu: ok=%v pominięte=%d", ok, sup)
	}
}
