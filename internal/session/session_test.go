package session_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/fakeserver"
	"github.com/melnykp/pomoc-zdalna-agent/internal/session"
	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

const deviceID = "7a0d1c2e-0000-4000-8000-000000000001"

func dial(t *testing.T, srv *fakeserver.Server) transport.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := transport.Dial(ctx, transport.DialOptions{URL: srv.WSURL(), DeviceID: deviceID})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(1000, "koniec testu") })
	return c
}

func params(priv ed25519.PrivateKey, keys ...ed25519.PublicKey) session.Params {
	return session.Params{DeviceID: deviceID, Private: priv, ServerKeys: keys, Versions: wire.Versions{Agent: "1.2.3"}, Caps: []string{"inventory"}}
}

func TestHandshakeApprovedDevice(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeserver.New(t)
	srv.SetDevice(deviceID, pub, "approved")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info, err := session.Handshake(ctx, dial(t, srv), params(priv, srv.Pub))
	if err != nil {
		t.Fatal(err)
	}
	if info.SessionID == "" || info.HeartbeatS != 30 || info.InventoryH != 6 {
		t.Fatalf("niepełna sesja: %+v", info)
	}
	a := <-srv.Auths
	if a.AgentVersion != "1.2.3" || len(a.Caps) != 1 {
		t.Fatalf("serwer dostał inne auth niż wysłano: %+v", a)
	}
}

func TestHandshakeRejectsUntrustedServerKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeserver.New(t)
	srv.SetDevice(deviceID, pub, "approved")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := session.Handshake(ctx, dial(t, srv), params(priv, other))
	if !errors.Is(err, session.ErrUntrustedServer) {
		t.Fatalf("podpis obcym kluczem serwera powinien być odrzucony, jest: %v", err)
	}
}

func TestHandshakeAcceptsAnyOfSeveralTrustedKeys(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeserver.New(t)
	srv.SetDevice(deviceID, pub, "approved")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := session.Handshake(ctx, dial(t, srv), params(priv, other, srv.Pub)); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeRejectionReasons(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	for _, tc := range []struct {
		status string
		reason string
		retry  int
	}{
		{"pending", wire.AuthFailPending, 1},
		{"blocked", wire.AuthFailBlocked, 0},
		{"retired", wire.AuthFailRetired, 0},
	} {
		t.Run(tc.status, func(t *testing.T) {
			srv := fakeserver.New(t)
			srv.SetDevice(deviceID, pub, tc.status)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := session.Handshake(ctx, dial(t, srv), params(priv, srv.Pub))
			var rej *session.RejectedError
			if !errors.As(err, &rej) || rej.Reason != tc.reason || rej.RetryS != tc.retry {
				t.Fatalf("oczekiwano odmowy %s (retry %d), jest: %v", tc.reason, tc.retry, err)
			}
		})
	}
}

func TestHandshakeBadSignatureAndUnknownDevice(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, intruder, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeserver.New(t)
	srv.SetDevice(deviceID, pub, "approved")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := session.Handshake(ctx, dial(t, srv), params(intruder, srv.Pub))
	var rej *session.RejectedError
	if !errors.As(err, &rej) || rej.Reason != wire.AuthFailBadSignature {
		t.Fatalf("obcy klucz urządzenia powinien dać bad_signature, jest: %v", err)
	}

	empty := fakeserver.New(t)
	_, err = session.Handshake(ctx, dial(t, empty), params(intruder, empty.Pub))
	if !errors.As(err, &rej) || rej.Reason != wire.AuthFailUnknownDevice {
		t.Fatalf("nieznane urządzenie powinno dać unknown_device, jest: %v", err)
	}
}

func TestHandshakeNeedsTrustedKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	srv := fakeserver.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := session.Handshake(ctx, dial(t, srv), params(priv)); err == nil {
		t.Fatal("bez zaufanych kluczy serwera handshake nie może się udać")
	}
}
