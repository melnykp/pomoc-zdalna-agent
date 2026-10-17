// Package commands odbiera polecenia z serwera i wykonuje je (docs/ARCHITECTURE.md):
// natychmiastowy cmd.ack, idempotencja po command_id, wynik trwały do cmd.result.ack.
//
// TODO: trwała kolejka wyników w state\ (JSON), odsyłanie zaległych po restarcie.
package commands

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Handler wykonuje polecenie jednego typu.
type Handler func(ctx context.Context, cmd wire.Cmd) (json.RawMessage, error)

// Kody błędów w CmdResult.Error.
const (
	ErrUnknownCommand = "unknown_command"
	ErrExpired        = "expired"
	ErrTimeout        = "timeout"
)

// Dispatcher kieruje polecenia do handlerów i pilnuje idempotencji.
type Dispatcher struct {
	mu       sync.Mutex
	handlers map[string]Handler
	seen     *ring
	timeout  time.Duration
}

// New tworzy dispatcher z limitem czasu na pojedyncze polecenie i pamięcią
// ostatnich 1000 identyfikatorów.
func New(timeout time.Duration) *Dispatcher {
	return &Dispatcher{handlers: map[string]Handler{}, seen: newRing(1000), timeout: timeout}
}

// Register rejestruje handler typu polecenia.
func (d *Dispatcher) Register(typ string, h Handler) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.handlers[typ] = h
}

// Execute wykonuje polecenie i zwraca wynik gotowy do wysłania. Drugi wynik true
// oznacza powtórzenie już widzianego command_id: polecenia nie wykonano i nic nie
// należy odsyłać poza ponownym cmd.ack.
func (d *Dispatcher) Execute(ctx context.Context, cmd wire.Cmd, now time.Time) (wire.CmdResult, bool) {
	d.mu.Lock()
	if d.seen.has(cmd.CommandID) {
		d.mu.Unlock()
		return wire.CmdResult{}, true
	}
	d.seen.add(cmd.CommandID)
	h, ok := d.handlers[cmd.Type]
	d.mu.Unlock()

	res := wire.CmdResult{CommandID: cmd.CommandID}
	if cmd.ExpiresAt > 0 && now.UnixMilli() > cmd.ExpiresAt {
		res.Error = ErrExpired
		return res, false
	}
	if !ok {
		res.Error = ErrUnknownCommand
		return res, false
	}

	cctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	start := time.Now()
	out, err := h(cctx, cmd)
	res.DurationMs = time.Since(start).Milliseconds()
	switch {
	case err == nil:
		res.OK = true
		res.Result = out
	case cctx.Err() == context.DeadlineExceeded:
		res.Error = ErrTimeout
	default:
		res.Error = fmt.Sprintf("%v", err)
	}
	return res, false
}

// ring pamięta ostatnie n identyfikatorów ze stałym kosztem pamięci.
type ring struct {
	ids []string
	idx map[string]struct{}
	pos int
}

func newRing(n int) *ring {
	return &ring{ids: make([]string, n), idx: make(map[string]struct{}, n)}
}

func (r *ring) has(id string) bool {
	_, ok := r.idx[id]
	return ok
}

func (r *ring) add(id string) {
	if old := r.ids[r.pos]; old != "" {
		delete(r.idx, old)
	}
	r.ids[r.pos] = id
	r.idx[id] = struct{}{}
	r.pos = (r.pos + 1) % len(r.ids)
}
