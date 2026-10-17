// Package transport utrzymuje połączenie WSS z bramką agenta (docs/ARCHITECTURE.md).
//
// Wymagania: TLS 1.3 minimum, ping co 20 s, limit ramki 256 KB (2 MB dla inventory.full),
// jedna sesja na urządzenie (pilnuje serwer), nagłówek X-Device-Id.
package transport

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Conn to połączenie z serwerem na poziomie kopert. Send jest bezpieczne współbieżnie.
type Conn interface {
	Send(ctx context.Context, env wire.Envelope) error
	Recv(ctx context.Context) (wire.Envelope, error)
	Ping(ctx context.Context) error
	Close(code int, reason string) error
}

// Limity ramek.
const (
	MaxFrameBytes          = 256 << 10
	MaxInventoryFrameBytes = 2 << 20
	PingInterval           = 20 * time.Second
	PingTimeout            = 10 * time.Second
	// maxIncomingBytes to limit ramki od serwera; polecenia są małe, zostawiamy zapas.
	maxIncomingBytes = 1 << 20
)

// PendingRetry to odstęp ponawiania po auth.fail{pending}, gdy serwer nie poda retry_s.
const PendingRetry = 10 * time.Minute

// DialOptions opisuje połączenie z bramką.
type DialOptions struct {
	// URL to adres kanału: wss://host/v1/agent (ws:// tylko dla localhost w rozwoju).
	URL      string
	DeviceID string
	// HTTPClient pozwala podmienić klienta (testy z własnym TLS). Domyślnie TLS 1.3.
	HTTPClient *http.Client
}

// NewHTTPClient zwraca klienta z TLS 1.3 jako minimum, bez przekierowań (kanał ma stały adres).
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS13},
			Proxy:                 http.ProxyFromEnvironment,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

type wsConn struct{ c *websocket.Conn }

// Dial otwiera kanał WebSocket.
func Dial(ctx context.Context, o DialOptions) (Conn, error) {
	client := o.HTTPClient
	if client == nil {
		// Timeout klienta obejmowałby całe życie połączenia, więc zostawiamy go pustym: czas dialu pilnuje ctx.
		client = NewHTTPClient(0)
	}
	c, _, err := websocket.Dial(ctx, o.URL, &websocket.DialOptions{
		HTTPClient: client,
		HTTPHeader: http.Header{"X-Device-Id": {o.DeviceID}, "User-Agent": {"rmm-agent"}},
	})
	if err != nil {
		return nil, fmt.Errorf("transport: połączenie z %s: %w", o.URL, err)
	}
	c.SetReadLimit(maxIncomingBytes)
	return &wsConn{c: c}, nil
}

func (w *wsConn) Send(ctx context.Context, env wire.Envelope) error {
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	limit := MaxFrameBytes
	if env.T == wire.TypeInventoryFull {
		limit = MaxInventoryFrameBytes
	}
	if len(raw) > limit {
		return fmt.Errorf("transport: wiadomość %s ma %d B, limit %d B", env.T, len(raw), limit)
	}
	return w.c.Write(ctx, websocket.MessageText, raw)
}

func (w *wsConn) Recv(ctx context.Context) (wire.Envelope, error) {
	typ, data, err := w.c.Read(ctx)
	if err != nil {
		return wire.Envelope{}, err
	}
	if typ != websocket.MessageText {
		return wire.Envelope{}, errors.New("transport: oczekiwano ramki tekstowej")
	}
	var env wire.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		return wire.Envelope{}, fmt.Errorf("transport: zła koperta: %w", err)
	}
	if env.V != wire.ProtocolVersion {
		return wire.Envelope{}, fmt.Errorf("transport: nieobsługiwana wersja protokołu %d", env.V)
	}
	return env, nil
}

func (w *wsConn) Ping(ctx context.Context) error { return w.c.Ping(ctx) }

func (w *wsConn) Close(code int, reason string) error {
	return w.c.Close(websocket.StatusCode(code), reason)
}

// CloseCode zwraca kod zamknięcia kanału z błędu (0, gdy to nie było zamknięcie protokołu).
func CloseCode(err error) int {
	return int(websocket.CloseStatus(err))
}

// Backoff to wykładnicza polityka ponawiania z losowym rozrzutem.
type Backoff struct {
	Min    time.Duration
	Max    time.Duration
	Jitter float64 // udział rozrzutu, np. 0.2 = ±20 %
}

// DefaultBackoff: 1 s → 5 min, ±20 %.
func DefaultBackoff() Backoff {
	return Backoff{Min: time.Second, Max: 5 * time.Minute, Jitter: 0.2}
}

// Next zwraca czas oczekiwania przed próbą numer attempt (liczoną od 0).
func (b Backoff) Next(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 30 {
		attempt = 30
	}
	d := b.Min << uint(attempt)
	if d <= 0 || d > b.Max {
		d = b.Max
	}
	if b.Jitter > 0 {
		f := 1 + (rand.Float64()*2-1)*b.Jitter
		d = time.Duration(float64(d) * f)
	}
	return d
}
