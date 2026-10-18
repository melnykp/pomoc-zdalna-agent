//go:build windows

package peer

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/engine"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recInjector zapisuje wstrzyknięte zdarzenia; fail != nil udaje błąd SendInput.
type recInjector struct {
	mu   sync.Mutex
	log  []string
	fail error
}

func (r *recInjector) add(s string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail != nil {
		return r.fail
	}
	r.log = append(r.log, s)
	return nil
}
func (r *recInjector) Move(float64, float64) error { return r.add("mm") }
func (r *recInjector) Wheel(int, int) error        { return r.add("wh") }
func (r *recInjector) Button(b int, down bool) error {
	return r.add(map[bool]string{true: "md", false: "mu"}[down])
}
func (r *recInjector) Key(c string, down bool) error {
	return r.add(map[bool]string{true: "kd:", false: "ku:"}[down] + c)
}
func (r *recInjector) entries() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// harness łączy prawdziwą sesję z widzem zbudowanym na pion (pętla zwrotna), z podmienianym źródłem certyfikatu zdalnego.
type harness struct {
	t             *testing.T
	sess          *Session
	viewer        *webrtc.PeerConnection
	ctrl, mouse   *webrtc.DataChannel
	inj           *recInjector
	states        chan string
	meta          chan string
	cursor        chan string
	engineStarted atomic.Bool
	ctrlOpen      chan struct{}
}

func newHarness(t *testing.T, cert func(real func() []byte) func() []byte, poll time.Duration, waitOpen bool) *harness {
	t.Helper()
	h := &harness{t: t, inj: &recInjector{}, states: make(chan string, 16), meta: make(chan string, 16), cursor: make(chan string, 64), ctrlOpen: make(chan struct{})}
	eng := engine.New(engine.Config{}, quietLogger())
	sess, err := New(Options{
		Engine: eng, Injector: h.inj, Log: quietLogger(),
		OnState: func(st string, _ wire.RemoteStats) {
			select {
			case h.states <- st:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.sess = sess
	sess.verifyPoll = poll
	sess.remoteCert = cert(sess.pionRemoteCert)
	sess.runEngine = func(ctx context.Context) error {
		h.engineStarted.Store(true)
		<-ctx.Done()
		return nil
	}
	t.Cleanup(sess.Close)

	me := &webrtc.MediaEngine{}
	if err := me.RegisterDefaultCodecs(); err != nil {
		t.Fatal(err)
	}
	se := webrtc.SettingEngine{}
	se.SetIncludeLoopbackCandidate(true)
	pc, err := webrtc.NewAPI(webrtc.WithMediaEngine(me), webrtc.WithSettingEngine(se)).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	h.viewer = pc
	t.Cleanup(func() { _ = pc.Close() })
	if _, err := pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo, webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		t.Fatal(err)
	}
	mk := func(label string, init *webrtc.DataChannelInit) *webrtc.DataChannel {
		dc, err := pc.CreateDataChannel(label, init)
		if err != nil {
			t.Fatal(err)
		}
		return dc
	}
	h.ctrl = mk("ctrl", nil)
	zero := uint16(0)
	unordered := false
	h.mouse = mk("mouse", &webrtc.DataChannelInit{Ordered: &unordered, MaxRetransmits: &zero})
	cur := mk("cursor", nil)
	meta := mk("meta", nil)
	h.ctrl.OnOpen(func() { close(h.ctrlOpen) })
	cur.OnMessage(func(m webrtc.DataChannelMessage) {
		select {
		case h.cursor <- string(m.Data):
		default:
		}
	})
	meta.OnMessage(func(m webrtc.DataChannelMessage) {
		select {
		case h.meta <- string(m.Data):
		default:
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		t.Fatal(err)
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if err := pc.SetLocalDescription(offer); err != nil {
		t.Fatal(err)
	}
	<-gather
	answer, _, err := sess.Answer(pc.LocalDescription().SDP)
	if err != nil {
		t.Fatal(err)
	}
	if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatal(err)
	}
	if !waitOpen {
		return h
	}
	select {
	case <-h.ctrlOpen:
	case <-time.After(15 * time.Second):
		t.Fatal("kanał ctrl nie otworzył się")
	}
	return h
}

func (h *harness) send(dc *webrtc.DataChannel, text string) {
	h.t.Helper()
	if err := dc.SendText(text); err != nil {
		h.t.Fatal(err)
	}
}

func waitMsg(t *testing.T, ch chan string, contains string, d time.Duration) string {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case m := <-ch:
			if strings.Contains(m, contains) {
				return m
			}
		case <-deadline:
			t.Fatalf("nie doczekano komunikatu zawierającego %q", contains)
			return ""
		}
	}
}

func eventually(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("nie doczekano: %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Regresja z testu na prawdziwym komputerze: obraz płynął, a wejście, kursor i lista monitorów nie działały, bo certyfikat zdalny
// był jeszcze pusty w chwili OnDataChannel, a handlery rejestrowano tylko po udanej weryfikacji, więc nie wracały nigdy.
func TestInputCursorAndMetaWorkWhenCertificateAppearsAfterChannelsOpen(t *testing.T) {
	var gate atomic.Bool
	h := newHarness(t, func(real func() []byte) func() []byte {
		return func() []byte {
			if !gate.Load() {
				return nil // handshake już zakończony, ale certyfikat jeszcze „niedostępny”
			}
			return real()
		}
	}, 20*time.Millisecond, true)

	h.send(h.ctrl, `{"t":"kd","c":"KeyA"}`)
	h.send(h.mouse, `{"t":"mm","x":0.5,"y":0.5}`)
	time.Sleep(400 * time.Millisecond)
	if got := h.inj.entries(); len(got) != 0 {
		t.Fatalf("przed weryfikacją nic nie może zostać wstrzyknięte: %v", got)
	}
	select {
	case m := <-h.meta:
		t.Fatalf("meta przed weryfikacją: %s", m)
	default:
	}
	if h.engineStarted.Load() || h.sess.verdict() != 0 {
		t.Fatalf("przed weryfikacją silnik nie startuje (engine=%v verdict=%d)", h.engineStarted.Load(), h.sess.verdict())
	}

	gate.Store(true) // certyfikat „pojawia się”
	waitMsg(t, h.meta, `"displays"`, 5*time.Second)
	eventually(t, "start silnika po weryfikacji", 5*time.Second, h.engineStarted.Load)
	eventually(t, "kanał kursora ustawiony po weryfikacji", 5*time.Second, func() bool {
		h.sess.mu.Lock()
		defer h.sess.mu.Unlock()
		return h.sess.cursor != nil
	})
	if h.sess.verdict() != 1 {
		t.Fatalf("verdict %d", h.sess.verdict())
	}

	// Te same kanały, bez ponownego otwierania, teraz przenoszą wejście.
	h.send(h.ctrl, `{"t":"kd","c":"KeyB"}`)
	eventually(t, "wstrzyknięcie po weryfikacji", 3*time.Second, func() bool {
		for _, e := range h.inj.entries() {
			if e == "kd:KeyB" {
				return true
			}
		}
		return false
	})
	for _, e := range h.inj.entries() {
		if e == "kd:KeyA" {
			t.Fatal("wejście odrzucone przed weryfikacją nie może zostać wykonane po niej")
		}
	}
	// Ping przez ctrl dostaje pong na meta (sprawdza obie strony: wejście i kanał odpowiedzi).
	h.send(h.ctrl, `{"t":"ping","tc":1}`)
	waitMsg(t, h.meta, `"pong"`, 3*time.Second)
}

func TestMismatchedCertificateClosesConnectionAndBlocksEverything(t *testing.T) {
	h := newHarness(t, func(func() []byte) func() []byte {
		return func() []byte { return []byte("obcy certyfikat DER") } // odcisk inny niż w ofercie
	}, 20*time.Millisecond, false) // przy niezgodności połączenie bywa zamknięte, zanim kanały zdążą się otworzyć
	for i := 0; i < 5; i++ {
		_ = h.ctrl.SendText(`{"t":"kd","c":"KeyA"}`)
		_ = h.mouse.SendText(`{"t":"mm","x":0.1,"y":0.1}`)
		time.Sleep(20 * time.Millisecond)
	}
	waitState(t, h.states, StateFailed, 5*time.Second)
	if h.sess.verdict() != -1 {
		t.Fatalf("verdict %d, oczekiwano -1", h.sess.verdict())
	}
	if got := h.inj.entries(); len(got) != 0 {
		t.Fatalf("niezgodny widz wstrzyknął: %v", got)
	}
	if h.engineStarted.Load() {
		t.Fatal("silnik nie może wystartować dla niezgodnego widza")
	}
	select {
	case m := <-h.meta:
		t.Fatalf("niezgodny widz dostał meta: %s", m)
	default:
	}
	// Połączenie jest zamknięte także po stronie widza.
	eventually(t, "zamknięcie połączenia po stronie widza", 15*time.Second, func() bool {
		st := h.viewer.ConnectionState()
		return st == webrtc.PeerConnectionStateClosed || st == webrtc.PeerConnectionStateFailed || st == webrtc.PeerConnectionStateDisconnected
	})
}

func TestMissingCertificateForeverClosesConnectionAfterPolls(t *testing.T) {
	h := newHarness(t, func(func() []byte) func() []byte { return func() []byte { return nil } }, 3*time.Millisecond, false)
	waitState(t, h.states, StateFailed, 5*time.Second)
	if h.engineStarted.Load() || len(h.inj.entries()) != 0 {
		t.Fatal("bez certyfikatu nic nie może ruszyć")
	}
	if h.sess.verdict() != 0 {
		t.Fatalf("brak certyfikatu to nie rozstrzygnięcie o niezgodności (verdict %d)", h.sess.verdict())
	}
}

func waitState(t *testing.T, ch chan string, want string, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case st := <-ch:
			if st == want {
				return
			}
		case <-deadline:
			t.Fatalf("nie doczekano stanu %q", want)
		}
	}
}

// ---- whenVerified i dzienniki na sesji bez sieci ----

func bareVerifySession(t *testing.T, remoteFP string, cert func() []byte, log *slog.Logger) *Session {
	t.Helper()
	eng := engine.New(engine.Config{}, quietLogger())
	inj := &recInjector{}
	return &Session{
		o: Options{Engine: eng, Injector: inj}, log: log, pressd: NewPressed(), remoteFP: remoteFP,
		remoteCert: cert, verifyPoll: 5 * time.Millisecond, rejectLog: newRateLimiter(time.Second), sendLog: newRateLimiter(time.Second), inputStats: &InputStats{}, chanOpen: map[string]bool{},
	}
}

func TestWhenVerifiedRunsImmediatelyLaterOrNever(t *testing.T) {
	der := []byte("certyfikat widza")
	fp := CertificateFingerprint(der)

	// Weryfikacja już przeszła: fn od razu, synchronicznie.
	s := bareVerifySession(t, fp, func() []byte { return der }, quietLogger())
	ran := false
	s.whenVerified("meta", func() { ran = true })
	if !ran {
		t.Fatal("przy gotowym certyfikacie fn ma się wykonać od razu")
	}

	// Certyfikat po chwili: fn dokładnie raz, po jego pojawieniu się.
	var ready atomic.Bool
	var runs atomic.Int32
	s2 := bareVerifySession(t, fp, func() []byte {
		if ready.Load() {
			return der
		}
		return nil
	}, quietLogger())
	s2.whenVerified("cursor", func() { runs.Add(1) })
	time.Sleep(60 * time.Millisecond)
	if runs.Load() != 0 {
		t.Fatal("fn nie może się wykonać przed pojawieniem się certyfikatu")
	}
	ready.Store(true)
	eventually(t, "fn po pojawieniu się certyfikatu", 2*time.Second, func() bool { return runs.Load() == 1 })
	time.Sleep(30 * time.Millisecond)
	if runs.Load() != 1 {
		t.Fatalf("fn wykonane %d razy", runs.Load())
	}

	// Niezgodny odcisk: fn nigdy, a sesja zamknięta (StateFailed).
	var failed atomic.Bool
	s3 := bareVerifySession(t, fp, func() []byte { return []byte("ktoś inny") }, quietLogger())
	s3.o.OnState = func(st string, _ wire.RemoteStats) { failed.Store(st == StateFailed) }
	var ran3 atomic.Bool
	s3.whenVerified("meta", func() { ran3.Store(true) })
	eventually(t, "zamknięcie po niezgodności", 2*time.Second, failed.Load)
	if ran3.Load() || s3.verdict() != -1 {
		t.Fatalf("niezgodny: fn=%v verdict=%d", ran3.Load(), s3.verdict())
	}

	// Sesja zakończona w trakcie oczekiwania: pętla przestaje próbować.
	var calls atomic.Int32
	s4 := bareVerifySession(t, fp, func() []byte { calls.Add(1); return nil }, quietLogger())
	s4.whenVerified("meta", func() { t.Error("fn po zakończeniu sesji") })
	time.Sleep(30 * time.Millisecond)
	s4.end(StateDisconnected)
	time.Sleep(30 * time.Millisecond)
	n := calls.Load()
	time.Sleep(60 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("pętla oczekiwania powinna się zatrzymać po końcu sesji")
	}
}

// captureHandler zbiera wpisy dziennika (poziom i tekst), żeby sprawdzić, co trafia do agent.log.
type captureHandler struct {
	mu      *sync.Mutex
	records *[]string
}

func (c captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.mu.Lock()
	*c.records = append(*c.records, r.Level.String()+" "+r.Message)
	c.mu.Unlock()
	return nil
}
func (c captureHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c captureHandler) WithGroup(string) slog.Handler      { return c }

func TestMismatchedCertificateOnInputRejectsFrameAndClosesSession(t *testing.T) {
	var failed atomic.Bool
	s := bareVerifySession(t, CertificateFingerprint([]byte("przypięty")), func() []byte { return []byte("podstawiony") }, quietLogger())
	s.o.OnState = func(st string, _ wire.RemoteStats) { failed.Store(st == StateFailed) }
	s.onChannelMessage("ctrl", []byte(`{"t":"kd","c":"KeyA"}`))
	if got := s.o.Injector.(*recInjector).entries(); len(got) != 0 {
		t.Fatalf("ramka od niezgodnego widza została wykonana: %v", got)
	}
	if !failed.Load() || s.verdict() != -1 {
		t.Fatalf("sesja powinna zostać zamknięta błędem (failed=%v verdict=%d)", failed.Load(), s.verdict())
	}
	// Kolejne ramki też odrzucone (sesja zakończona), nic nie przecieka.
	s.onChannelMessage("mouse", []byte(`{"t":"mm","x":0.2,"y":0.2}`))
	if got := s.o.Injector.(*recInjector).entries(); len(got) != 0 {
		t.Fatalf("wstrzyknięto po zamknięciu: %v", got)
	}
}

func TestRejectedInputIsLoggedAtInfoOncePerSecond(t *testing.T) {
	var mu sync.Mutex
	var recs []string
	s := bareVerifySession(t, CertificateFingerprint([]byte("x")), func() []byte { return nil }, slog.New(captureHandler{mu: &mu, records: &recs}))
	for i := 0; i < 50; i++ {
		s.onChannelMessage("ctrl", []byte(`{"t":"kd","c":"KeyA"}`))
	}
	mu.Lock()
	defer mu.Unlock()
	rejected := 0
	for _, r := range recs {
		if strings.HasPrefix(r, "INFO wejście odrzucone") {
			rejected++
		}
	}
	if rejected != 1 {
		t.Fatalf("wpisów o odrzuconym wejściu %d, oczekiwano 1 (reszta ograniczona do 1/s): %v", rejected, recs)
	}
	if got := s.o.Injector.(*recInjector).entries(); len(got) != 0 {
		t.Fatalf("wstrzyknięto mimo braku weryfikacji: %v", got)
	}
}

func TestSendInputErrorsAreLoggedAsWarnWithRateLimit(t *testing.T) {
	var mu sync.Mutex
	var recs []string
	s := bareVerifySession(t, "", nil, slog.New(captureHandler{mu: &mu, records: &recs}))
	s.o.Injector.(*recInjector).fail = errors.New("SendInput(klawisz): Access is denied")
	for i := 0; i < 30; i++ {
		s.onInput([]byte(`{"t":"kd","c":"KeyA"}`))
	}
	mu.Lock()
	defer mu.Unlock()
	warns := 0
	for _, r := range recs {
		if strings.HasPrefix(r, "WARN wstrzykiwanie wejścia nieudane") {
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("ostrzeżeń %d, oczekiwano 1 na sekundę: %v", warns, recs)
	}
}

func TestViewOnlySessionLogsWhyInputIsIgnored(t *testing.T) {
	var mu sync.Mutex
	var recs []string
	s := bareVerifySession(t, "", nil, slog.New(captureHandler{mu: &mu, records: &recs}))
	s.o.Injector = nil
	s.onInput([]byte(`{"t":"kd","c":"KeyA"}`))
	mu.Lock()
	defer mu.Unlock()
	if len(recs) != 1 || !strings.HasPrefix(recs[0], "INFO wejście odrzucone") {
		t.Fatalf("wpisy: %v", recs)
	}
}

// inputMsg czeka na komunikat "input" z kanału meta spełniający warunek.
func waitInputMsg(t *testing.T, h *harness, d time.Duration, cond func(InputStatsMsg) bool) InputStatsMsg {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case raw := <-h.meta:
			if !strings.Contains(raw, `"t":"input"`) {
				continue
			}
			var m InputStatsMsg
			if err := json.Unmarshal([]byte(raw), &m); err != nil {
				t.Fatal(err)
			}
			if cond(m) {
				return m
			}
		case <-deadline:
			t.Fatal("nie doczekano komunikatu o wejściu spełniającego warunek")
			return InputStatsMsg{}
		}
	}
}

// Widz sam pokazuje, na którym etapie ginie wejście: liczniki odebrane/odrzucone/wstrzyknięte/błędy, kanały i weryfikacja DTLS.
func TestInputStatsReachViewerThroughMetaChannel(t *testing.T) {
	h := newHarness(t, func(real func() []byte) func() []byte { return real }, 20*time.Millisecond, true)
	h.send(h.ctrl, `{"t":"kd","c":"ShiftLeft"}`)
	h.send(h.ctrl, `{"t":"ku","c":"ShiftLeft"}`)
	h.send(h.mouse, `{"t":"mm","x":0.5,"y":0.5}`)
	h.send(h.ctrl, `{"t":"ping","tc":1}`) // nie jest zdarzeniem wejścia: odebrane, ale niewstrzykiwane

	m := waitInputMsg(t, h, 10*time.Second, func(m InputStatsMsg) bool { return m.Injected >= 3 })
	if m.Rx.Ctrl < 3 || m.Rx.Mouse < 1 || m.Errors != 0 || m.Rejected != 0 || m.Injected != 3 {
		t.Fatalf("liczniki: %+v", m)
	}
	for _, ch := range []string{"ctrl", "mouse", "cursor", "meta"} {
		if !m.Channels[ch] {
			t.Fatalf("kanał %s powinien być otwarty: %+v", ch, m.Channels)
		}
	}
	if m.DTLS != "zgodny" || !m.Control {
		t.Fatalf("stan: dtls=%q control=%v", m.DTLS, m.Control)
	}

	// Błąd SendInput trafia do widza razem z treścią (kod systemu i pulpity w komunikacie błędu).
	h.inj.mu.Lock()
	h.inj.fail = errors.New("SendInput(klawisz): przyjęto 0 z 1, błąd systemu 5, pulpit wątku \"Default\", pulpit wejściowy \"Winlogon\"")
	h.inj.mu.Unlock()
	h.send(h.ctrl, `{"t":"kd","c":"KeyA"}`)
	m = waitInputMsg(t, h, 10*time.Second, func(m InputStatsMsg) bool { return m.Errors >= 1 })
	if !strings.Contains(m.LastError, "Winlogon") || m.Injected != 3 {
		t.Fatalf("błąd wstrzykiwania: %+v", m)
	}
}

// Przed weryfikacją odrzucone ramki widać w licznikach (rx rośnie, injected nie), z powodem.
func TestInputStatsShowRejectedFramesBeforeVerification(t *testing.T) {
	var gate atomic.Bool
	h := newHarness(t, func(real func() []byte) func() []byte {
		return func() []byte {
			if !gate.Load() {
				return nil
			}
			return real()
		}
	}, 20*time.Millisecond, true)
	for i := 0; i < 4; i++ {
		h.send(h.ctrl, `{"t":"kd","c":"KeyA"}`)
	}
	time.Sleep(200 * time.Millisecond)
	snap := h.sess.inputStats.Snapshot()
	if snap.Rx.Ctrl != 4 || snap.Rejected != 4 || snap.Injected != 0 || !strings.Contains(snap.LastReject, "DTLS") {
		t.Fatalf("przed weryfikacją: %+v", snap)
	}
	gate.Store(true)
	m := waitInputMsg(t, h, 10*time.Second, func(m InputStatsMsg) bool { return m.DTLS == "zgodny" })
	if m.Rejected != 4 || m.Injected != 0 {
		t.Fatalf("po weryfikacji liczniki odrzuconych zostają: %+v", m)
	}
}
