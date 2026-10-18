package remote

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

const testViewerFP = "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:0E:64:B4:8B:A4:9D:D3:11:1D:4F:0C"

// fakeProc udaje pomocnika: zapisuje, co dostał, i pozwala testowi wstrzykiwać komunikaty z drugiej strony.
type fakeProc struct {
	mu     sync.Mutex
	sent   []ipc.DesktopMsg
	msgs   chan ipc.DesktopMsg
	killed bool
	closed bool
	// autoReady: po uruchomieniu od razu zgłasza gotowość; autoAnswer: na start odpowiada answer z odciskiem.
	autoReady, autoAnswer bool
	closeOnStop           bool
}

func newFakeProc() *fakeProc { return &fakeProc{msgs: make(chan ipc.DesktopMsg, 16)} }

func (f *fakeProc) Send(m ipc.DesktopMsg) error {
	f.mu.Lock()
	f.sent = append(f.sent, m)
	f.mu.Unlock()
	switch {
	case m.Kind == ipc.DesktopStart && f.autoAnswer:
		f.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopAnswer, SessionID: m.SessionID, SDP: "v=0 answer", Fingerprint: "AA:BB"}
	case m.Kind == ipc.DesktopStop && f.closeOnStop:
		f.close()
	}
	return nil
}

func (f *fakeProc) Messages() <-chan ipc.DesktopMsg { return f.msgs }

func (f *fakeProc) Kill() {
	f.mu.Lock()
	f.killed = true
	f.mu.Unlock()
	f.close()
}

func (f *fakeProc) close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	f.closed = true
	close(f.msgs)
}

func (f *fakeProc) wasKilled() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.killed
}

func (f *fakeProc) kinds() []ipc.DesktopKind {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ipc.DesktopKind
	for _, m := range f.sent {
		out = append(out, m.Kind)
	}
	return out
}

func (f *fakeProc) first() ipc.DesktopMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sent[0]
}

// procList to uruchomione atrapy pomocnika (chronione, bo test czyta je z innej gorutyny).
type procList struct {
	mu sync.Mutex
	ps []*fakeProc
}

func (l *procList) add(p *fakeProc) { l.mu.Lock(); l.ps = append(l.ps, p); l.mu.Unlock() }
func (l *procList) count() int      { l.mu.Lock(); defer l.mu.Unlock(); return len(l.ps) }
func (l *procList) at(i int) *fakeProc {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ps[i]
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newTestEngine(t *testing.T, launch func() *fakeProc) (*Engine, *procList) {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, HelperExeName)
	if err := os.WriteFile(exe, []byte("MZ"), 0o755); err != nil {
		t.Fatal(err)
	}
	procs := &procList{}
	e := NewEngine(exe, quietLog())
	e.Verify = nil // weryfikację skrótu testuje osobny przypadek
	e.Launch = func(context.Context, string, *slog.Logger) (Process, error) {
		p := launch()
		procs.add(p)
		if p.autoReady {
			p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopReady, Version: "1.2.3", Displays: []ipc.DesktopDisplay{{Index: 0, Width: 1920, Height: 1080}}}
		}
		return p, nil
	}
	return e, procs
}

func offerSig(sessionID string) wire.RemoteSignal {
	return wire.RemoteSignal{SessionID: sessionID, Kind: wire.SignalOffer, SDP: "v=0 offer", Fingerprint: testViewerFP}
}

func readyAnswering() *fakeProc {
	p := newFakeProc()
	p.autoReady, p.autoAnswer, p.closeOnStop = true, true, true
	return p
}

func TestEngineImplementsOptionalInterfaces(t *testing.T) {
	var m Module = &Engine{}
	if _, ok := m.(Signaler); !ok {
		t.Fatal("Engine musi być Signaler")
	}
	if _, ok := m.(SessionEnder); !ok {
		t.Fatal("Engine musi być SessionEnder")
	}
	if n, ok := m.(EngineNamer); !ok || n.Engine() != wire.RemoteEngineWebRTC {
		t.Fatal("Engine musi nazywać się webrtc")
	}
	if _, ok := m.(Installer); !ok {
		t.Fatal("Engine musi umieć instalować pomocnika z komponentu remote_module")
	}
	if _, ok := m.(VersionedInstaller); !ok {
		t.Fatal("Engine musi zapisywać wersję przy instalacji")
	}
}

func TestOfferLaunchesHelperAndReturnsAnswerWithFingerprint(t *testing.T) {
	e, procs := newTestEngine(t, readyAnswering)
	servers := []wire.ICEServer{{URLs: []string{"stun:s.example.pl"}}}
	sig := offerSig("s1")
	sig.ICEServers = servers
	out, err := e.Signal(context.Background(), "s1", sig)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kind != wire.SignalAnswer || out.SDP != "v=0 answer" || out.Fingerprint != "AA:BB" || out.SessionID != "s1" {
		t.Fatalf("odpowiedź: %+v", out)
	}
	p := procs.at(0)
	start := p.first()
	// Pomocnik dostaje przypięty odcisk widza, żeby sam sprawdzić certyfikat DTLS.
	if start.Kind != ipc.DesktopStart || start.SDP != "v=0 offer" || start.Fingerprint != testViewerFP || !start.Control || len(start.ICEServers) != 1 {
		t.Fatalf("start: %+v", start)
	}
	if ok, _ := e.Connected(context.Background()); ok {
		t.Fatal("przed zgłoszeniem connected nie ma połączenia")
	}
	p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopState, State: ipc.StateConnected}
	waitFor(t, func() bool { ok, _ := e.Connected(context.Background()); return ok })

	// Kandydat widza idzie do pomocnika bez odpowiedzi.
	if rep, err := e.Signal(context.Background(), "s1", wire.RemoteSignal{SessionID: "s1", Kind: wire.SignalCandidate, Candidate: "candidate:1 1 udp 1 10.0.0.1 5000 typ host", SDPMid: "0"}); err != nil || rep != nil {
		t.Fatalf("kandydat: rep=%v err=%v", rep, err)
	}
	if k := p.kinds(); len(k) != 2 || k[1] != ipc.DesktopSignal {
		t.Fatalf("komunikaty do pomocnika: %v", k)
	}

	// Koniec sesji: stop, pomocnik oddaje statystyki i się kończy; EndSession zwraca je do audytu.
	p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopState, State: ipc.StateDisconnected, Stats: &wire.RemoteStats{DurationMs: 4200, BytesOut: 99, Frames: 7}}
	waitFor(t, func() bool { ok, _ := e.Connected(context.Background()); return !ok })
	st := e.EndSession(context.Background())
	if st == nil || st.BytesOut != 99 || st.Frames != 7 {
		t.Fatalf("statystyki: %+v", st)
	}
	if k := p.kinds(); k[len(k)-1] != ipc.DesktopStop {
		t.Fatalf("ostatni komunikat powinien być stop: %v", k)
	}
	if e.EndSession(context.Background()) != nil {
		t.Fatal("drugie EndSession nie ma czego oddać")
	}
	// Wersja z komunikatu ready (bez uruchamiania pliku).
	if v := e.Version(context.Background()); v != "1.2.3" {
		t.Fatalf("wersja %q", v)
	}
}

func TestOfferRequiresViewerFingerprint(t *testing.T) {
	e, procs := newTestEngine(t, readyAnswering)
	sig := offerSig("s1")
	sig.Fingerprint = ""
	if _, err := e.Signal(context.Background(), "s1", sig); err == nil {
		t.Fatal("oferta bez odcisku widza musi zostać odrzucona")
	}
	if procs.count() != 0 {
		t.Fatal("bez odcisku pomocnik nie może wystartować")
	}
}

func TestOfferFailsWhenHelperReportsFailure(t *testing.T) {
	e, procs := newTestEngine(t, func() *fakeProc { p := newFakeProc(); p.autoReady, p.closeOnStop = true, true; return p })
	go func() {
		waitFor(t, func() bool { return procs.count() == 1 && len(procs.at(0).kinds()) == 1 })
		procs.at(0).msgs <- ipc.DesktopMsg{Kind: ipc.DesktopState, State: ipc.StateFailed, Error: "koder niedostępny"}
	}()
	_, err := e.Signal(context.Background(), "s1", offerSig("s1"))
	if err == nil || err.Error() != "pomocnik pulpitu: koder niedostępny" {
		t.Fatalf("błąd: %v", err)
	}
	if e.cur != nil {
		t.Fatal("po błędzie pomocnik ma być zakończony")
	}
}

func TestOfferKillsHelperThatNeverGetsReady(t *testing.T) {
	e, procs := newTestEngine(t, newFakeProc)
	go func() {
		waitFor(t, func() bool { return procs.count() == 1 })
		procs.at(0).close() // pomocnik pada przed ready
	}()
	if _, err := e.Signal(context.Background(), "s1", offerSig("s1")); err == nil {
		t.Fatal("oczekiwano błędu")
	}
}

func TestNewOfferReplacesRunningHelper(t *testing.T) {
	e, procs := newTestEngine(t, readyAnswering)
	ctx := context.Background()
	if _, err := e.Signal(ctx, "s1", offerSig("s1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Signal(ctx, "s1", offerSig("s1")); err != nil {
		t.Fatal(err)
	}
	if procs.count() != 2 {
		t.Fatalf("pomocników: %d", procs.count())
	}
	if k := procs.at(0).kinds(); k[len(k)-1] != ipc.DesktopStop {
		t.Fatalf("pierwszy pomocnik powinien dostać stop: %v", k)
	}
}

func TestParallelOffersDoNotOrphanHelpers(t *testing.T) {
	// Pomocnik odpowiada dopiero, gdy test pozwoli: w tym czasie przychodzi druga oferta.
	release := make(chan struct{})
	e, procs := newTestEngine(t, func() *fakeProc {
		p := newFakeProc()
		p.autoReady, p.closeOnStop = true, true
		go func() {
			<-release
			waitFor(t, func() bool { return len(p.kinds()) >= 1 })
			p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopAnswer, SDP: "v=0 answer", Fingerprint: "AA:BB"}
		}()
		return p
	})
	ctx := context.Background()
	var busy atomic.Int32
	var okCount atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.Signal(ctx, "s1", offerSig("s1"))
			switch {
			case err == nil:
				okCount.Add(1)
			case errors.Is(err, ErrOfferInProgress):
				busy.Add(1)
			default:
				t.Errorf("niespodziewany błąd: %v", err)
			}
		}()
	}
	waitFor(t, func() bool { return procs.count() == 1 })
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if okCount.Load() != 1 || busy.Load() != 3 {
		t.Fatalf("udanych %d, zajętych %d (oczekiwano 1 i 3)", okCount.Load(), busy.Load())
	}
	if procs.count() != 1 {
		t.Fatalf("równoległe oferty uruchomiły %d pomocników", procs.count())
	}
	// Jedyny pomocnik jest w ewidencji i kończy się z sesją.
	e.EndSession(ctx)
	waitFor(t, func() bool { k := procs.at(0).kinds(); return len(k) > 0 && k[len(k)-1] == ipc.DesktopStop })
}

func TestEndSessionDuringLaunchKillsFreshHelper(t *testing.T) {
	// Launch blokuje się do czasu, aż test zakończy sesję: świeży proces ma zostać zabity, nie osierocony.
	started := make(chan struct{})
	unblock := make(chan struct{})
	e, procs := newTestEngine(t, readyAnswering)
	inner := e.Launch
	e.Launch = func(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
		close(started)
		<-unblock
		return inner(ctx, exe, log)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := e.Signal(context.Background(), "s1", offerSig("s1"))
		errc <- err
	}()
	<-started
	if e.EndSession(context.Background()) != nil {
		t.Fatal("przed startem nie ma statystyk")
	}
	close(unblock)
	if err := <-errc; !errors.Is(err, ErrNoSession) {
		t.Fatalf("oferta po zamknięciu sesji: %v", err)
	}
	waitFor(t, func() bool { return procs.count() == 1 && procs.at(0).wasKilled() })
	if e.cur != nil {
		t.Fatal("brak ewidencji po zamknięciu")
	}
}

func TestOfferStopsWhenSessionContextEnds(t *testing.T) {
	// Pomocnik gotowy, ale nie odpowiada; kontekst sesji gaśnie (remote.close w trakcie oferty).
	e, procs := newTestEngine(t, func() *fakeProc { p := newFakeProc(); p.autoReady, p.closeOnStop = true, true; return p })
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := e.Signal(ctx, "s1", offerSig("s1"))
		errc <- err
	}()
	waitFor(t, func() bool { return procs.count() == 1 && len(procs.at(0).kinds()) == 1 })
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("błąd: %v", err)
	}
	k := procs.at(0).kinds()
	if k[len(k)-1] != ipc.DesktopStop {
		t.Fatalf("pomocnik powinien dostać stop: %v", k)
	}
	if e.cur != nil {
		t.Fatal("brak ewidencji po anulowaniu")
	}
}

func TestCandidateWithoutSessionIsRejected(t *testing.T) {
	e, _ := newTestEngine(t, newFakeProc)
	_, err := e.Signal(context.Background(), "s1", wire.RemoteSignal{Kind: wire.SignalCandidate, Candidate: "c"})
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("błąd: %v", err)
	}
}

func TestOfferNeedsInstalledHelper(t *testing.T) {
	e := NewEngine(filepath.Join(t.TempDir(), "brak.exe"), nil)
	if e.Installed() {
		t.Fatal("brak pliku = niezainstalowany")
	}
	_, err := e.Signal(context.Background(), "s1", offerSig("s1"))
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("błąd: %v", err)
	}
}

func TestVerifyRefusesHelperWithoutMatchingHash(t *testing.T) {
	e, procs := newTestEngine(t, readyAnswering)
	manifest := e.manifestPath()
	e.Verify = func(exe string) error { return VerifyHelperHash(exe, manifest) }
	// Bez pliku bocznego (pomocnik skopiowany ręcznie, nie komponentem) usługa odmawia uruchomienia.
	if _, err := e.Signal(context.Background(), "s1", offerSig("s1")); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("bez pliku bocznego: %v", err)
	}
	if procs.count() != 0 {
		t.Fatal("niezweryfikowany pomocnik nie może wystartować")
	}
	// Instalacja komponentem zapisuje skrót: od tej pory uruchomienie przechodzi.
	src := filepath.Join(t.TempDir(), "nowy.exe")
	if err := os.WriteFile(src, []byte("MZ-nowy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.InstallVersion(context.Background(), src, "0.5.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Signal(context.Background(), "s1", offerSig("s1")); err != nil {
		t.Fatalf("po instalacji: %v", err)
	}
	e.EndSession(context.Background())
	// Podmieniony plik (inny skrót niż w pliku bocznym) znów nie startuje.
	if err := os.WriteFile(e.Exe, []byte("MZ-podstawiony"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Signal(context.Background(), "s1", offerSig("s1")); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("podstawiony plik: %v", err)
	}
	if procs.count() != 1 {
		t.Fatalf("pomocników uruchomionych: %d", procs.count())
	}
}

func TestInstallVersionWritesManifestAndVersionDoesNotExecute(t *testing.T) {
	dir := t.TempDir()
	e := NewEngine(filepath.Join(dir, HelperExeName), nil)
	src := filepath.Join(dir, "nowy.exe")
	if err := os.WriteFile(src, []byte("MZ-nowy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Exe, []byte("MZ-stary"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.InstallVersion(context.Background(), src, "0.4.1"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(e.Exe)
	if string(got) != "MZ-nowy" {
		t.Fatalf("zawartość: %q", got)
	}
	if _, err := os.Stat(e.Exe + ".new"); err == nil {
		t.Fatal("plik tymczasowy powinien zniknąć")
	}
	if err := VerifyHelperHash(e.Exe, e.manifestPath()); err != nil {
		t.Fatalf("skrót po instalacji: %v", err)
	}
	// Wersja z pliku bocznego; plik „wykonywalny” to śmieci, więc każde uruchomienie by padło.
	if v := e.Version(context.Background()); v != "0.4.1" {
		t.Fatalf("wersja %q", v)
	}
	// Install bez wersji też zapisuje skrót (wersja pusta).
	if err := e.Install(context.Background(), src); err != nil {
		t.Fatal(err)
	}
	if v := e.Version(context.Background()); v != "" {
		t.Fatalf("wersja po Install bez wersji %q", v)
	}
}

func TestManagerRoutesSignalOnlyToCurrentSession(t *testing.T) {
	e, _ := newTestEngine(t, readyAnswering)
	rec := &recorder{}
	m := NewManager(Options{Module: e, Emit: rec.emit, Log: quietLog()})
	ctx := context.Background()
	if _, err := m.Signal(ctx, "s1", offerSig("s1")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("bez otwartej sesji: %v", err)
	}
	s, err := m.Open(ctx, "s1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.Engine != wire.RemoteEngineWebRTC || s.RemoteID != "webrtc" {
		t.Fatalf("sesja: %+v", s)
	}
	if _, err := m.Signal(ctx, "inna", offerSig("inna")); !errors.Is(err, ErrNoSession) {
		t.Fatalf("obca sesja: %v", err)
	}
	out, err := m.Signal(ctx, "s1", offerSig("s1"))
	if err != nil || out.Kind != wire.SignalAnswer {
		t.Fatalf("oferta: %+v %v", out, err)
	}
	// Zamknięcie sesji kończy pomocnika i zgłasza stan.
	if err := m.Close(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if ev := rec.list(); len(ev) != 1 || ev[0] != "s1:closed" {
		t.Fatalf("zdarzenia: %v", ev)
	}
	if e.cur != nil {
		t.Fatal("pomocnik powinien być zakończony")
	}
}

func TestManagerCloseDuringOfferCancelsIt(t *testing.T) {
	// Pomocnik gotowy, ale bez odpowiedzi; remote.close w trakcie oferty przerywa ją i zabija pomocnika.
	e, procs := newTestEngine(t, func() *fakeProc { p := newFakeProc(); p.autoReady, p.closeOnStop = true, true; return p })
	m := NewManager(Options{Module: e, Emit: (&recorder{}).emit, Log: quietLog()})
	ctx := context.Background()
	if _, err := m.Open(ctx, "s1", 0); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := m.Signal(ctx, "s1", offerSig("s1"))
		errc <- err
	}()
	waitFor(t, func() bool { return procs.count() == 1 && len(procs.at(0).kinds()) == 1 })
	if err := m.Close(ctx, "s1"); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err == nil {
		t.Fatal("oferta powinna zostać przerwana")
	}
	k := procs.at(0).kinds()
	if k[len(k)-1] != ipc.DesktopStop {
		t.Fatalf("pomocnik powinien dostać stop: %v", k)
	}
	if e.cur != nil {
		t.Fatal("po zamknięciu sesji nie ma pomocnika w ewidencji")
	}
}

func TestManagerWithoutSignalerRejectsSignal(t *testing.T) {
	m, _, _, _ := newManager(t)
	if _, err := m.Signal(context.Background(), "s1", wire.RemoteSignal{Kind: wire.SignalOffer}); !errors.Is(err, ErrNoSignaling) {
		t.Fatalf("błąd: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("nie doczekano warunku")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
