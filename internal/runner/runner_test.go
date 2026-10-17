package runner_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/fakeserver"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/inventory"
	"github.com/melnykp/pomoc-zdalna-agent/internal/runner"
	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

const deviceID = "7a0d1c2e-0000-4000-8000-000000000001"

type env struct {
	srv     *fakeserver.Server
	pub     ed25519.PublicKey
	opts    runner.Options
	cfgPath string
}

func setup(t *testing.T, status string) *env {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	srv := fakeserver.New(t)
	srv.SetDevice(deviceID, pub, status)

	cfg := config.Default()
	cfg.ServerURL = srv.URL()
	cfg.DeviceID = deviceID
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	return &env{
		srv: srv, pub: pub, cfgPath: cfgPath,
		opts: runner.Options{
			Cfg:      cfg,
			CfgPath:  cfgPath,
			Identity: &identity.Identity{Public: pub, Private: priv},
			Log:      slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})),
			Versions: wire.Versions{Agent: "9.9.9"},
			Keys:     func(config.Config) ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{srv.Pub}, nil },
			Inventory: func(context.Context) (inventory.Inventory, error) {
				return inventory.Inventory{OS: inventory.OS{Family: "windows", Hostname: "PC"}, Disks: []inventory.Disk{}, Network: []inventory.NetworkAdapter{}, Software: []inventory.Software{}}, nil
			},
			Backoff:        transport.Backoff{Min: 20 * time.Millisecond, Max: 100 * time.Millisecond},
			MinPendingWait: 50 * time.Millisecond,
			BlockedWait:    time.Hour,
			RetiredWait:    time.Hour,
			RejectedWait:   time.Hour,
			UntrustedWait:  time.Hour,
		},
	}
}

func start(t *testing.T, e *env) (*runner.Runner, context.CancelFunc) {
	t.Helper()
	r := runner.New(e.opts)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = r.Run(ctx); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("runner nie zakończył się po anulowaniu")
		}
	})
	return r, cancel
}

// next czeka na wiadomość danego typu od agenta, pomijając inne.
func next(t *testing.T, srv *fakeserver.Server, typ string) wire.Envelope {
	t.Helper()
	deadline := time.After(8 * time.Second)
	for {
		select {
		case m := <-srv.Received:
			if m.T == typ {
				return m
			}
		case <-deadline:
			t.Fatalf("brak wiadomości %s w 8 s", typ)
		}
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("nie doczekano: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cmd(t *testing.T, id, typ string, payload any) wire.Envelope {
	t.Helper()
	raw, _ := json.Marshal(payload)
	env, err := wire.NewEnvelope(wire.TypeCmd, wire.Cmd{CommandID: id, Type: typ, Payload: raw, ExpiresAt: time.Now().Add(time.Minute).UnixMilli()})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestSendsHeartbeatAndInventoryAfterConnect(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)

	hb := next(t, e.srv, wire.TypeHeartbeat)
	var h wire.Heartbeat
	if err := hb.Decode(&h); err != nil {
		t.Fatal(err)
	}
	if h.Versions.Agent != "9.9.9" || h.IPLocal == nil {
		t.Fatalf("heartbeat: %+v", h)
	}
	inv := next(t, e.srv, wire.TypeInventoryFull)
	var i inventory.Inventory
	if err := inv.Decode(&i); err != nil || i.OS.Hostname != "PC" {
		t.Fatalf("inwentaryzacja: %+v err=%v", i, err)
	}
	a := <-e.srv.Auths
	if a.AgentVersion != "9.9.9" {
		t.Fatalf("auth: %+v", a)
	}
}

func TestCommandIsAckedExecutedAndResultSent(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })
	next(t, e.srv, wire.TypeInventoryFull) // pierwsza inwentaryzacja po połączeniu

	if err := e.srv.Send(deviceID, cmd(t, "c-1", wire.CmdInventoryRefresh, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var ack wire.CmdAck
	if err := next(t, e.srv, wire.TypeCmdAck).Decode(&ack); err != nil || ack.CommandID != "c-1" {
		t.Fatalf("ack: %+v err=%v", ack, err)
	}
	next(t, e.srv, wire.TypeInventoryFull) // odświeżenie na żądanie
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.CommandID != "c-1" || !res.OK {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestUnknownCommandReturnsFailureResult(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	if err := e.srv.Send(deviceID, cmd(t, "c-2", "polecenie.ktorego.nie.ma", map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.OK || res.Error != "unknown_command" {
		t.Fatalf("polecenie bez obsługi powinno zwrócić unknown_command: %+v", res)
	}
}

func TestDuplicateCommandIsNotExecutedTwice(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	for i := 0; i < 2; i++ {
		if err := e.srv.Send(deviceID, cmd(t, "c-dup", wire.CmdRemoteOpen, map[string]any{})); err != nil {
			t.Fatal(err)
		}
	}
	results := 0
	acks := 0
	deadline := time.After(1500 * time.Millisecond)
loop:
	for {
		select {
		case m := <-e.srv.Received:
			switch m.T {
			case wire.TypeCmdResult:
				results++
			case wire.TypeCmdAck:
				acks++
			}
		case <-deadline:
			break loop
		}
	}
	if acks != 2 || results != 1 {
		t.Fatalf("powtórka powinna dostać ack, ale nie drugi wynik: acks=%d results=%d", acks, results)
	}
}

func TestConfigSetIsValidatedSavedAndApplied(t *testing.T) {
	e := setup(t, "approved")
	r, _ := start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	if err := e.srv.Send(deviceID, cmd(t, "c-bad", wire.CmdConfigSet, map[string]any{"heartbeat_s": 1})); err != nil {
		t.Fatal(err)
	}
	var bad wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&bad); err != nil || bad.OK {
		t.Fatalf("zakres 5..600 powinien odrzucić 1 s: %+v err=%v", bad, err)
	}
	if r.Config().HeartbeatSeconds != 30 {
		t.Fatal("odrzucona zmiana nie może zmienić konfiguracji")
	}

	if err := e.srv.Send(deviceID, cmd(t, "c-ok", wire.CmdConfigSet, map[string]any{"heartbeat_s": 45, "inventory_h": 12})); err != nil {
		t.Fatal(err)
	}
	var ok wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&ok); err != nil || !ok.OK {
		t.Fatalf("poprawna zmiana: %+v err=%v", ok, err)
	}
	if got := r.Config(); got.HeartbeatSeconds != 45 || got.InventoryHours != 12 {
		t.Fatalf("konfiguracja w pamięci: %+v", got)
	}
	saved, err := config.Load(e.cfgPath)
	if err != nil || saved.HeartbeatSeconds != 45 || saved.InventoryHours != 12 {
		t.Fatalf("zapisana konfiguracja: %+v err=%v", saved, err)
	}
}

func TestReconnectsAfterConnectionDrop(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)
	waitFor(t, "pierwsze połączenie", func() bool { return e.srv.Connections() == 1 && e.srv.Connected(deviceID) })

	e.srv.Drop(deviceID)
	waitFor(t, "ponowne połączenie", func() bool { return e.srv.Connections() == 2 && e.srv.Connected(deviceID) })
}

func TestPendingDeviceRetriesAndConnectsAfterApproval(t *testing.T) {
	e := setup(t, "pending")
	start(t, e)

	time.Sleep(300 * time.Millisecond)
	if e.srv.Connections() != 0 {
		t.Fatal("oczekujące urządzenie nie może być połączone")
	}
	e.srv.SetStatus(deviceID, "approved")
	// Serwer atrapy podaje retry_s=1, więc ponowna próba przychodzi w ciągu około sekundy.
	waitFor(t, "połączenie po zatwierdzeniu", func() bool { return e.srv.Connected(deviceID) })
}

func TestBlockedDeviceBacksOffForLong(t *testing.T) {
	e := setup(t, "blocked")
	start(t, e)
	time.Sleep(500 * time.Millisecond)
	if e.srv.Connections() != 0 {
		t.Fatal("zablokowane urządzenie nie może się połączyć")
	}
	// BlockedWait to godzina, więc nie ma lawiny prób: jedno uwierzytelnienie, bez ponowień.
	if len(e.srv.Auths) != 1 {
		t.Fatalf("oczekiwano jednej próby uwierzytelnienia, jest %d", len(e.srv.Auths))
	}
}

func TestUntrustedServerIsNeverTalkedTo(t *testing.T) {
	e := setup(t, "approved")
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	e.opts.Keys = func(config.Config) ([]ed25519.PublicKey, error) { return []ed25519.PublicKey{other}, nil }
	start(t, e)

	time.Sleep(500 * time.Millisecond)
	select {
	case m := <-e.srv.Received:
		t.Fatalf("agent wysłał %s do niezaufanego serwera", m.T)
	default:
	}
}

func TestRestartAndRetireCallbacksRunAfterResult(t *testing.T) {
	e := setup(t, "approved")
	restarted := make(chan struct{}, 1)
	retired := make(chan struct{}, 1)
	e.opts.OnRestart = func() { restarted <- struct{}{} }
	e.opts.OnRetire = func() { retired <- struct{}{} }
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	if err := e.srv.Send(deviceID, cmd(t, "c-r", wire.CmdAgentRestart, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil || !res.OK {
		t.Fatalf("wynik restartu: %+v err=%v", res, err)
	}
	select {
	case <-restarted:
	case <-time.After(5 * time.Second):
		t.Fatal("OnRestart nie został wywołany")
	}

	if err := e.srv.Send(deviceID, cmd(t, "c-x", wire.CmdDeviceRetire, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil || !res.OK {
		t.Fatalf("wynik wycofania: %+v err=%v", res, err)
	}
	select {
	case <-retired:
	case <-time.After(6 * time.Second):
		t.Fatal("OnRetire nie został wywołany")
	}
}
