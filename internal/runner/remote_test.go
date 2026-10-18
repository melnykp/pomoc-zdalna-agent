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

// elevDesktop to moduł pulpitu z obsługą podniesienia uprawnień (jak własny silnik): zapamiętuje prośby, odpowiada zadanym wynikiem i notuje,
// czy zgoda została aktywowana (po potwierdzeniu serwera) czy anulowana.
type elevDesktop struct {
	*fakeDesktop
	emu       sync.Mutex
	out       remote.ElevationOutcome
	calls     []string
	requests  []remote.ElevationRequest
	activated []string
	cancelled []string
}

func (d *elevDesktop) Elevate(_ context.Context, req remote.ElevationRequest) (remote.ElevationOutcome, error) {
	d.emu.Lock()
	defer d.emu.Unlock()
	d.calls = append(d.calls, req.SessionID+"|"+req.Engineer)
	d.requests = append(d.requests, req)
	return d.out, nil
}

func (d *elevDesktop) ActivateElevation(sessionID string) error {
	d.emu.Lock()
	defer d.emu.Unlock()
	d.activated = append(d.activated, sessionID)
	return nil
}

func (d *elevDesktop) CancelElevation(sessionID string) {
	d.emu.Lock()
	defer d.emu.Unlock()
	d.cancelled = append(d.cancelled, sessionID)
}

func (d *elevDesktop) seen() []string {
	d.emu.Lock()
	defer d.emu.Unlock()
	return append([]string(nil), d.calls...)
}

func (d *elevDesktop) outcomes() (activated, cancelled []string) {
	d.emu.Lock()
	defer d.emu.Unlock()
	return append([]string(nil), d.activated...), append([]string(nil), d.cancelled...)
}

func elevateMsg(t *testing.T, sessionID, requestID, engineer string) wire.Envelope {
	t.Helper()
	env, err := wire.NewEnvelope(wire.TypeRemoteElevate, wire.RemoteElevate{SessionID: sessionID, RequestID: requestID, Engineer: engineer, EngineerLogin: "jan@example.test", Tenant: "Kancelaria Lis"})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func elevAckMsg(t *testing.T, sessionID, requestID string, accepted bool) wire.Envelope {
	t.Helper()
	env, err := wire.NewEnvelope(wire.TypeRemoteElevAck, wire.RemoteElevationAck{SessionID: sessionID, RequestID: requestID, Accepted: accepted})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// Prośba inżyniera o podniesienie uprawnień dociera do modułu bieżącej sesji z nazwą, loginem i firmą, a wynik wraca do serwera z tym samym
// identyfikatorem prośby (serwer łączy odpowiedź z prośbą i zapisuje ją w audycie).
func TestRemoteElevateIsPassedToModuleAndAnswered(t *testing.T) {
	e := setup(t, "approved")
	mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationDenied, Reason: "użytkownik na komputerze odmówił"}}
	startWithRemote(t, e, mod)
	_ = e.srv.Send(deviceID, cmd(t, "r-e1", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-e1"}))
	next(t, e.srv, wire.TypeRemoteOTP)

	if err := e.srv.Send(deviceID, elevateMsg(t, "sess-e1", "req-1", "Jan Kowalski")); err != nil {
		t.Fatal(err)
	}
	var got wire.RemoteElevation
	if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.SessionID != "sess-e1" || got.RequestID != "req-1" || got.State != wire.ElevationDenied || got.Reason == "" {
		t.Fatalf("remote.elevation: %+v", got)
	}
	if seen := mod.seen(); len(seen) != 1 || seen[0] != "sess-e1|Jan Kowalski" {
		t.Fatalf("moduł dostał: %v", seen)
	}
	mod.emu.Lock()
	req := mod.requests[0]
	mod.emu.Unlock()
	if req.RequestID != "req-1" || req.Login != "jan@example.test" || req.Tenant != "Kancelaria Lis" {
		t.Fatalf("dane prośby dla okna zgody: %+v", req)
	}
	// Odmowa nie czeka na potwierdzenie i niczego nie aktywuje ani nie anuluje.
	if a, c := mod.outcomes(); len(a) != 0 || len(c) != 0 {
		t.Fatalf("odmowa: aktywowano %v, anulowano %v", a, c)
	}
}

// Zgoda użytkownika podnosi poziom pomocnika dopiero po potwierdzeniu serwera (remote.elevation.ack); odrzucone, spóźnione albo nieobecne
// potwierdzenie, a także zerwanie połączenia po "Tak" anulują zgodę, więc audyt nigdy nie rozmija się z faktycznym poziomem.
func TestRemoteElevateRaisesOnlyAfterServerConfirmation(t *testing.T) {
	t.Run("potwierdzone", func(t *testing.T) {
		e := setup(t, "approved")
		mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationGranted, Reason: "ok"}}
		startWithRemote(t, e, mod)
		_ = e.srv.Send(deviceID, cmd(t, "r-g1", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-g1"}))
		next(t, e.srv, wire.TypeRemoteOTP)
		_ = e.srv.Send(deviceID, elevateMsg(t, "sess-g1", "req-g1", "Jan"))
		var got wire.RemoteElevation
		if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil || got.State != wire.ElevationGranted {
			t.Fatalf("%+v %v", got, err)
		}
		// Zgoda wysłana, ale jeszcze nic nie podniesiono.
		time.Sleep(100 * time.Millisecond)
		if a, c := mod.outcomes(); len(a) != 0 || len(c) != 0 {
			t.Fatalf("przed potwierdzeniem: aktywowano %v, anulowano %v", a, c)
		}
		_ = e.srv.Send(deviceID, elevAckMsg(t, "sess-g1", "req-g1", true))
		waitFor(t, "aktywacja po potwierdzeniu", func() bool { a, _ := mod.outcomes(); return len(a) == 1 && a[0] == "sess-g1" })
		if _, c := mod.outcomes(); len(c) != 0 {
			t.Fatalf("anulowano mimo potwierdzenia: %v", c)
		}
	})
	t.Run("serwer odrzucił zgodę", func(t *testing.T) {
		e := setup(t, "approved")
		mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationGranted}}
		startWithRemote(t, e, mod)
		_ = e.srv.Send(deviceID, cmd(t, "r-g2", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-g2"}))
		next(t, e.srv, wire.TypeRemoteOTP)
		_ = e.srv.Send(deviceID, elevateMsg(t, "sess-g2", "req-g2", "Jan"))
		next(t, e.srv, wire.TypeRemoteElevation)
		_ = e.srv.Send(deviceID, elevAckMsg(t, "sess-g2", "req-g2", false))
		waitFor(t, "anulowanie po odrzuceniu", func() bool { _, c := mod.outcomes(); return len(c) == 1 })
		if a, _ := mod.outcomes(); len(a) != 0 {
			t.Fatalf("odrzucona zgoda nie może podnieść poziomu: %v", a)
		}
	})
	t.Run("brak potwierdzenia", func(t *testing.T) {
		e := setup(t, "approved")
		e.opts.ElevationAckWait = 150 * time.Millisecond
		mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationGranted}}
		startWithRemote(t, e, mod)
		_ = e.srv.Send(deviceID, cmd(t, "r-g3", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-g3"}))
		next(t, e.srv, wire.TypeRemoteOTP)
		_ = e.srv.Send(deviceID, elevateMsg(t, "sess-g3", "req-g3", "Jan"))
		next(t, e.srv, wire.TypeRemoteElevation)
		waitFor(t, "anulowanie bez potwierdzenia", func() bool { _, c := mod.outcomes(); return len(c) == 1 })
		// Spóźnione potwierdzenie niczego już nie podnosi.
		_ = e.srv.Send(deviceID, elevAckMsg(t, "sess-g3", "req-g3", true))
		time.Sleep(150 * time.Millisecond)
		if a, _ := mod.outcomes(); len(a) != 0 {
			t.Fatalf("spóźnione potwierdzenie podniosło poziom: %v", a)
		}
	})
	t.Run("zerwane połączenie po Tak", func(t *testing.T) {
		e := setup(t, "approved")
		mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationGranted}}
		startWithRemote(t, e, mod)
		_ = e.srv.Send(deviceID, cmd(t, "r-g4", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-g4"}))
		next(t, e.srv, wire.TypeRemoteOTP)
		_ = e.srv.Send(deviceID, elevateMsg(t, "sess-g4", "req-g4", "Jan"))
		next(t, e.srv, wire.TypeRemoteElevation)
		e.srv.Drop(deviceID)
		waitFor(t, "anulowanie po zerwaniu połączenia", func() bool { _, c := mod.outcomes(); return len(c) == 1 })
		if a, _ := mod.outcomes(); len(a) != 0 {
			t.Fatalf("zgoda bez potwierdzenia nie może podnieść poziomu: %v", a)
		}
	})
}

func TestRemoteElevateForUnknownSessionOrBadDataAnswersWithoutAsking(t *testing.T) {
	e := setup(t, "approved")
	mod := &elevDesktop{fakeDesktop: &fakeDesktop{installed: true}, out: remote.ElevationOutcome{State: wire.ElevationGranted}}
	startWithRemote(t, e, mod)
	_ = e.srv.Send(deviceID, cmd(t, "r-e2", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-e2"}))
	next(t, e.srv, wire.TypeRemoteOTP)

	// Cudza sesja: błąd, a moduł nie dostaje prośby (nie pokazujemy użytkownikowi okna zgody dla nieistniejącej sesji).
	_ = e.srv.Send(deviceID, elevateMsg(t, "inna-sesja", "req-3", "Jan"))
	var got wire.RemoteElevation
	if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req-3" || got.State != wire.ElevationError || len(mod.seen()) != 0 {
		t.Fatalf("cudza sesja: %+v, moduł dostał %v", got, mod.seen())
	}

	// Za długie dane (nazwa, login) są odrzucane przed użyciem; za długi identyfikator prośby jest ignorowany po cichu (nie ma komu odpowiedzieć).
	long := strings.Repeat("x", 400)
	_ = e.srv.Send(deviceID, elevateMsg(t, "sess-e2", "req-long", long))
	if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req-long" || got.State != wire.ElevationError || len(mod.seen()) != 0 {
		t.Fatalf("za długa nazwa: %+v, moduł dostał %v", got, mod.seen())
	}
	_ = e.srv.Send(deviceID, elevateMsg(t, "sess-e2", strings.Repeat("r", 100), "Jan"))
	// Prośba bez identyfikatora też jest ignorowana, a następna poprawna działa (żaden poprzedni przypadek jej nie zablokował).
	_ = e.srv.Send(deviceID, elevateMsg(t, "sess-e2", "", "Jan"))
	_ = e.srv.Send(deviceID, elevateMsg(t, "sess-e2", "req-4", "Jan"))
	if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != "req-4" {
		t.Fatalf("po błędnych prośbach działa następna: %+v", got)
	}
}

func TestRemoteElevateWithModuleWithoutSupportIsUnavailable(t *testing.T) {
	e := setup(t, "approved")
	startWithRemote(t, e, &fakeDesktop{installed: true}) // jak RustDesk: bez Elevator
	_ = e.srv.Send(deviceID, cmd(t, "r-e3", wire.CmdRemoteOpen, wire.RemoteOpenPayload{SessionID: "sess-e3"}))
	next(t, e.srv, wire.TypeRemoteOTP)
	_ = e.srv.Send(deviceID, elevateMsg(t, "sess-e3", "req-5", "Jan"))
	var got wire.RemoteElevation
	if err := next(t, e.srv, wire.TypeRemoteElevation).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.State != wire.ElevationUnavailable {
		t.Fatalf("moduł bez obsługi: %+v", got)
	}
}
