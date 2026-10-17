// Package fakeserver to atrapa bramki agenta do testów: mówi protokół v1 z docs/ARCHITECTURE.md
// (hello, auth z weryfikacją podpisu, auth.ok z podpisem serwera, auth.fail) i /v1/enroll.
// Nie jest używana w kodzie produkcyjnym.
package fakeserver

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/melnykp/pomoc-zdalna-agent/internal/protocol"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Device to urządzenie znane atrapie.
type Device struct {
	Pub    ed25519.PublicKey
	Status string // pending, approved, blocked, retired
}

// Server to atrapa bramki.
type Server struct {
	HTTP    *httptest.Server
	mux     *http.ServeMux
	Pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	t       testing.TB
	mu      sync.Mutex
	devices map[string]*Device
	conns   map[string]*websocket.Conn
	// Received zbiera wiadomości agenta po uwierzytelnieniu.
	Received chan wire.Envelope
	// Auths zbiera wiadomości auth (do sprawdzania wersji i możliwości).
	Auths chan wire.Auth
	// EnrollResponse, gdy ustawione, jest zwracane z POST /v1/enroll; w przeciwnym razie 401.
	EnrollHandler func(body map[string]any) (int, any)
	// Connections liczy udane uwierzytelnienia.
	connections int
}

// New uruchamia atrapę na losowym porcie.
func New(t testing.TB) *Server {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Pub:      pub,
		priv:     priv,
		t:        t,
		devices:  map[string]*Device{},
		conns:    map[string]*websocket.Conn{},
		Received: make(chan wire.Envelope, 256),
		Auths:    make(chan wire.Auth, 64),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/agent", s.handleAgent)
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	s.mux = mux
	s.HTTP = httptest.NewServer(mux)
	t.Cleanup(s.HTTP.Close)
	return s
}

// URL zwraca adres HTTP atrapy (do server_url i enroll).
func (s *Server) URL() string { return s.HTTP.URL }

// WSURL zwraca adres kanału agenta.
func (s *Server) WSURL() string { return "ws" + strings.TrimPrefix(s.HTTP.URL, "http") + "/v1/agent" }

// SetDevice dodaje albo zmienia urządzenie.
func (s *Server) SetDevice(id string, pub ed25519.PublicKey, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[id] = &Device{Pub: pub, Status: status}
}

// SetStatus zmienia status urządzenia bez rozłączania.
func (s *Server) SetStatus(id, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d := s.devices[id]; d != nil {
		d.Status = status
	}
}

// Connections zwraca liczbę udanych uwierzytelnień.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connections
}

// Connected mówi, czy urządzenie ma otwarty kanał.
func (s *Server) Connected(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[id] != nil
}

// Send wysyła wiadomość do uwierzytelnionego urządzenia.
func (s *Server) Send(id string, env wire.Envelope) error {
	s.mu.Lock()
	c := s.conns[id]
	s.mu.Unlock()
	if c == nil {
		return context.Canceled
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Write(ctx, websocket.MessageText, raw)
}

// Drop zamyka kanał urządzenia (symulacja zerwania połączenia).
func (s *Server) Drop(id string) {
	s.mu.Lock()
	c := s.conns[id]
	s.mu.Unlock()
	if c != nil {
		_ = c.Close(websocket.StatusGoingAway, "test")
	}
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, `{"code":"validation"}`, http.StatusBadRequest)
		return
	}
	status, resp := http.StatusUnauthorized, any(map[string]string{"code": "enrollment_invalid", "message": "Zaproszenie wygasło albo jest nieprawidłowe"})
	if s.EnrollHandler != nil {
		status, resp = s.EnrollHandler(body)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleAgent(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Device-Id")
	if id == "" {
		http.Error(w, "brak X-Device-Id", http.StatusBadRequest)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	defer c.CloseNow()
	ctx := r.Context()

	serverNonce, _ := protocol.NewNonce()
	send := func(env wire.Envelope) {
		raw, _ := json.Marshal(env)
		_ = c.Write(ctx, websocket.MessageText, raw)
	}
	hello, _ := wire.NewEnvelope(wire.TypeHello, wire.Hello{ServerNonce: serverNonce, ServerKeyID: "test", ProtocolVersions: []int{1}, Time: time.Now().UnixMilli()})
	send(hello)

	_, data, err := c.Read(ctx)
	if err != nil {
		return
	}
	var env wire.Envelope
	if json.Unmarshal(data, &env) != nil || env.T != wire.TypeAuth {
		_ = c.Close(websocket.StatusCode(4002), "expected auth")
		return
	}
	var auth wire.Auth
	if env.Decode(&auth) != nil || auth.DeviceID != id {
		_ = c.Close(websocket.StatusCode(4002), "bad auth")
		return
	}
	select {
	case s.Auths <- auth:
	default:
	}

	fail := func(reason string, retry int) {
		f, _ := wire.Reply(env, wire.TypeAuthFail, wire.AuthFail{Reason: reason, RetryS: retry})
		send(f)
		_ = c.Close(websocket.StatusCode(4003), reason)
	}

	s.mu.Lock()
	dev := s.devices[id]
	s.mu.Unlock()
	if dev == nil {
		fail(wire.AuthFailUnknownDevice, 0)
		return
	}
	sig, err := protocol.DecodeSig(auth.Sig)
	if err != nil || !protocol.VerifyAgentAuth(dev.Pub, serverNonce, auth.AgentNonce, id, sig) {
		fail(wire.AuthFailBadSignature, 0)
		return
	}
	s.mu.Lock()
	status := dev.Status
	s.mu.Unlock()
	switch status {
	case "pending":
		fail(wire.AuthFailPending, 1)
		return
	case "blocked":
		fail(wire.AuthFailBlocked, 0)
		return
	case "retired":
		fail(wire.AuthFailRetired, 0)
		return
	}

	okSig := protocol.EncodeSig(protocol.SignServerAuth(s.priv, serverNonce, auth.AgentNonce, id))
	ok, _ := wire.Reply(env, wire.TypeAuthOK, wire.AuthOK{SessionID: "00000000-0000-4000-8000-000000000001", HeartbeatS: 30, InventoryH: 6, Time: time.Now().UnixMilli(), Sig: okSig})
	send(ok)

	s.mu.Lock()
	s.connections++
	s.conns[id] = c
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.conns[id] == c {
			delete(s.conns, id)
		}
		s.mu.Unlock()
	}()

	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		var m wire.Envelope
		if json.Unmarshal(data, &m) != nil {
			continue
		}
		select {
		case s.Received <- m:
		default:
		}
	}
}

// Handle dodaje trasę HTTP (np. pobieranie artefaktów wydań) do atrapy.
func (s *Server) Handle(pattern string, h http.HandlerFunc) { s.mux.HandleFunc(pattern, h) }
