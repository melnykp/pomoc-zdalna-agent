package runner_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/remote"
	"github.com/melnykp/pomoc-zdalna-agent/internal/runner"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// fakeDesktop udaje klienta pulpitu na komputerze.
type fakeDesktop struct {
	mu        sync.Mutex
	installed bool
	passwords []string
}

func (f *fakeDesktop) Installed() bool                    { return f.installed }
func (f *fakeDesktop) ID(context.Context) (string, error) { return "987654321", nil }
func (f *fakeDesktop) EnsureConfig(context.Context) error { return nil }
func (f *fakeDesktop) Running(context.Context) bool       { return f.installed }
func (f *fakeDesktop) Connected(context.Context) (bool, error) {
	return false, nil
}
func (f *fakeDesktop) SetPassword(_ context.Context, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passwords = append(f.passwords, pw)
	return nil
}

func (f *fakeDesktop) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.passwords) == 0 {
		return ""
	}
	return f.passwords[len(f.passwords)-1]
}

// startWithRemote uruchamia runnera z menedżerem pulpitu, którego zdarzenia trafiają do runnera (jak w main.go).
func startWithRemote(t *testing.T, e *env, mod remote.Module) *remote.Manager {
	t.Helper()
	var rr atomic.Pointer[runner.Runner]
	mgr := remote.NewManager(remote.Options{
		Module: mod,
		Emit: func(sessionID, state string, stats *wire.RemoteStats) {
			if r := rr.Load(); r != nil {
				r.SendRemoteState(sessionID, state, stats)
			}
		},
		Poll: 20 * time.Millisecond,
	})
	e.opts.Remote = mgr
	r, _ := start(t, e)
	rr.Store(r)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })
	return mgr
}

func TestRemoteOpenSendsOneTimePasswordOverChannelNotInResult(t *testing.T) {
	e := setup(t, "approved")
	mod := &fakeDesktop{installed: true}
	startWithRemote(t, e, mod)

	if err := e.srv.Send(deviceID, cmd(t, "r-1", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-1", TTLS: 120})); err != nil {
		t.Fatal(err)
	}
	var otp wire.RemoteOTP
	if err := next(t, e.srv, wire.TypeRemoteOTP).Decode(&otp); err != nil {
		t.Fatal(err)
	}
	if otp.SessionID != "sess-1" || otp.RemoteID != "987654321" || len(otp.OTP) != remote.OTPLength || otp.ExpiresAt <= time.Now().UnixMilli() {
		t.Fatalf("remote.otp: %+v", otp)
	}
	if mod.last() != otp.OTP {
		t.Fatal("hasło wysłane serwerowi musi być tym samym, które ustawiono w kliencie pulpitu")
	}

	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || strings.Contains(string(res.Result), otp.OTP) {
		t.Fatalf("wynik polecenia (trafia do bazy) nie może zawierać hasła: %+v", res)
	}
}

func TestRemoteCloseLocksAccessAndReportsState(t *testing.T) {
	e := setup(t, "approved")
	mod := &fakeDesktop{installed: true}
	startWithRemote(t, e, mod)

	_ = e.srv.Send(deviceID, cmd(t, "r-2", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-2"}))
	var otp wire.RemoteOTP
	if err := next(t, e.srv, wire.TypeRemoteOTP).Decode(&otp); err != nil {
		t.Fatal(err)
	}

	_ = e.srv.Send(deviceID, cmd(t, "r-3", wire.CmdRemoteClose, wire.RemoteClosePayload{SessionID: "sess-2"}))
	var st wire.RemoteState
	if err := next(t, e.srv, wire.TypeRemoteState).Decode(&st); err != nil {
		t.Fatal(err)
	}
	if st.SessionID != "sess-2" || st.State != remote.StateClosed {
		t.Fatalf("remote.state: %+v", st)
	}
	if mod.last() == otp.OTP || len(mod.last()) != 48 {
		t.Fatalf("po zamknięciu sesji klient ma mieć hasło zamykające, jest: %q", mod.last())
	}
}

func TestRemoteOpenFailsClearlyWithoutModule(t *testing.T) {
	e := setup(t, "approved")
	startWithRemote(t, e, &fakeDesktop{installed: false})

	_ = e.srv.Send(deviceID, cmd(t, "r-4", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-4"}))
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.Error, "modułu pulpitu") {
		t.Fatalf("brak klienta pulpitu powinien dać czytelny błąd: %+v", res)
	}
}

func TestRemoteCommandsAreRejectedWhenModuleDisabled(t *testing.T) {
	e := setup(t, "approved") // bez opts.Remote
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })

	_ = e.srv.Send(deviceID, cmd(t, "r-5", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-5"}))
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil {
		t.Fatal(err)
	}
	if res.OK || !strings.Contains(res.Error, "wyłączony") {
		t.Fatalf("wyłączony moduł powinien odrzucić polecenie: %+v", res)
	}
}

func TestRemoteStartupLocksAccessAfterCrash(t *testing.T) {
	e := setup(t, "approved")
	mod := &fakeDesktop{installed: true}
	startWithRemote(t, e, mod)
	waitFor(t, "hasło zamykające po starcie", func() bool { return len(mod.last()) == 48 })
}
