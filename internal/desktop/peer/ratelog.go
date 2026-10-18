package peer

import (
	"sync"
	"time"
)

// rateLimiter przepuszcza pierwsze zdarzenie od razu, a kolejne najwyżej raz na interval; allow zwraca też, ile zdarzeń
// pominięto od ostatniego przepuszczonego (do dopisku w logu). Służy do logów, które inaczej zalałyby plik przy każdym ruchu myszy.
type rateLimiter struct {
	mu         sync.Mutex
	interval   time.Duration
	now        func() time.Time
	last       time.Time
	suppressed int
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{interval: interval, now: time.Now}
}

func (r *rateLimiter) allow() (ok bool, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t := r.now()
	if !r.last.IsZero() && t.Sub(r.last) < r.interval {
		r.suppressed++
		return false, 0
	}
	r.last = t
	suppressed = r.suppressed
	r.suppressed = 0
	return true, suppressed
}
