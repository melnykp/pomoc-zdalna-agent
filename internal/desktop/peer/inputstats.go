package peer

import (
	"sync"
	"sync/atomic"
	"time"
)

// InputStats zlicza drogę wejścia od widza do systemu, żeby widz sam pokazywał, na którym etapie wejście ginie:
// odebrane z kanałów → odrzucone (bramka weryfikacji DTLS, koniec sesji, tryb tylko-podgląd) → wstrzyknięte bez błędu albo z błędem SendInput.
type InputStats struct {
	RxCtrl   atomic.Int64 // ramki odebrane z kanału ctrl
	RxMouse  atomic.Int64 // ramki odebrane z kanału mouse
	Rejected atomic.Int64 // odrzucone przed wstrzyknięciem
	Injected atomic.Int64 // zdarzenia wejścia wstrzyknięte bez błędu
	Errors   atomic.Int64 // zdarzenia, przy których SendInput zwrócił błąd
	Mismatch atomic.Int64 // ruchy myszy, po których kursor nie jest tam, dokąd go wysłano (ciche odrzucenie)

	mu            sync.Mutex
	lastErr       string
	lastErrAt     time.Time
	lastMismatch  string
	lastRejectWhy string
}

// NoteError zapamiętuje ostatni błąd SendInput.
func (s *InputStats) NoteError(text string) {
	s.Errors.Add(1)
	s.mu.Lock()
	s.lastErr, s.lastErrAt = text, time.Now()
	s.mu.Unlock()
}

// NoteMismatch zapamiętuje ostatnią rozbieżność celu i położenia kursora.
func (s *InputStats) NoteMismatch(text string) {
	s.Mismatch.Add(1)
	s.mu.Lock()
	s.lastMismatch = text
	s.mu.Unlock()
}

// NoteReject zapamiętuje powód ostatniego odrzucenia.
func (s *InputStats) NoteReject(why string) {
	s.Rejected.Add(1)
	s.mu.Lock()
	s.lastRejectWhy = why
	s.mu.Unlock()
}

// InputStatsMsg to komunikat kanału "meta" ze stanem wejścia, wysyłany co ok. sekundę.
type InputStatsMsg struct {
	T            string          `json:"t"` // zawsze "input"
	Rx           InputRx         `json:"rx"`
	Rejected     int64           `json:"rejected"`
	Injected     int64           `json:"injected"`
	Errors       int64           `json:"errors"`
	Mismatch     int64           `json:"mismatch"`
	LastError    string          `json:"last_error,omitempty"`
	LastMismatch string          `json:"last_mismatch,omitempty"`
	LastReject   string          `json:"last_reject,omitempty"`
	Channels     map[string]bool `json:"channels"`
	DTLS         string          `json:"dtls"`    // zgodny | niezgodny | oczekuje
	Control      bool            `json:"control"` // false = sesja tylko do podglądu
	// Proc i FG to kontekst procesu i okna na pierwszym planie (pola z winput.ProcessContext / ForegroundInfo); typ dowolny,
	// żeby ten plik nie zależał od Windows.
	Proc any `json:"proc,omitempty"`
	FG   any `json:"fg,omitempty"`
}

// InputRx to liczniki odebranych ramek.
type InputRx struct {
	Ctrl  int64 `json:"ctrl"`
	Mouse int64 `json:"mouse"`
}

// Snapshot buduje komunikat ze stanu liczników; kanały, DTLS i kontekst dokłada wołający.
func (s *InputStats) Snapshot() InputStatsMsg {
	s.mu.Lock()
	defer s.mu.Unlock()
	return InputStatsMsg{
		T:            "input",
		Rx:           InputRx{Ctrl: s.RxCtrl.Load(), Mouse: s.RxMouse.Load()},
		Rejected:     s.Rejected.Load(),
		Injected:     s.Injected.Load(),
		Errors:       s.Errors.Load(),
		Mismatch:     s.Mismatch.Load(),
		LastError:    s.lastErr,
		LastMismatch: s.lastMismatch,
		LastReject:   s.lastRejectWhy,
	}
}

// DTLSLabel zamienia rozstrzygnięcie weryfikacji (0, 1, -1) na etykietę dla widza.
func DTLSLabel(verdict int) string {
	switch {
	case verdict > 0:
		return "zgodny"
	case verdict < 0:
		return "niezgodny"
	}
	return "oczekuje"
}
