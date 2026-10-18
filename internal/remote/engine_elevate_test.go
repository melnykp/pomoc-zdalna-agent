package remote

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// consentStub podstawia okno zgody: zlicza pytania, zapamiętuje, co dostało, i odpowiada zadaną decyzją (albo czeka na release).
type consentStub struct {
	mu       sync.Mutex
	calls    int
	last     ConsentRequest
	decision ConsentDecision
	err      error
	release  chan struct{} // gdy ustawiony, Ask czeka na zamknięcie kanału albo ctx
	onAsk    func()        // wołane w chwili pokazania okna (test sprawdza, co pomocnik już dostał)
}

func (c *consentStub) ask(ctx context.Context, req ConsentRequest) (ConsentDecision, error) {
	c.mu.Lock()
	c.calls++
	c.last = req
	rel, d, err, on := c.release, c.decision, c.err, c.onAsk
	c.mu.Unlock()
	if on != nil {
		on()
	}
	if rel != nil {
		select {
		case <-rel:
		case <-ctx.Done():
			return ConsentDenied, ctx.Err()
		}
	}
	return d, err
}

func (c *consentStub) count() int { c.mu.Lock(); defer c.mu.Unlock(); return c.calls }
func (c *consentStub) request() ConsentRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// elevHarness to silnik z atrapą pomocnika i okna zgody oraz zapisem poziomów, z jakimi startował pomocnik, i zgłoszeń startów.
type elevHarness struct {
	e       *Engine
	procs   *procList
	consent *consentStub
	mu      sync.Mutex
	levels  []string
	starts  []startReport
}

type startReport struct {
	session   string
	choice    TokenChoice
	level     string
	byRequest bool
}

func (h *elevHarness) launchedLevels() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.levels...)
}

func (h *elevHarness) startReports() []startReport {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]startReport(nil), h.starts...)
}

func newElevHarness(t *testing.T, level string) *elevHarness {
	t.Helper()
	e, procs := newTestEngine(t, readyAnswering)
	e.HelperLevel = level
	h := &elevHarness{e: e, procs: procs, consent: &consentStub{decision: ConsentAllowed}}
	inner := e.Launch
	e.Launch = func(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
		lvl := e.launchLevel()
		h.mu.Lock()
		h.levels = append(h.levels, lvl)
		h.mu.Unlock()
		kind := TokenUserRequested
		if lvl == config.DesktopHelperIntegrity {
			kind = TokenIntegrity
		}
		e.recordChoice(TokenChoice{Kind: kind, Level: lvl, Elevation: "limited"})
		return inner(ctx, exe, log)
	}
	e.OnHelperStart = func(session string, c TokenChoice, lvl string, byRequest bool) {
		h.mu.Lock()
		h.starts = append(h.starts, startReport{session, c, lvl, byRequest})
		h.mu.Unlock()
	}
	e.CanElevate = func() bool { return true }
	e.Consent = h.consent.ask
	e.UACOff = func() bool { return false }
	e.ReconnectWindow = 5 * time.Second
	e.PromptGap = -1 // wyłączony; odstęp ma osobny test
	e.StopGrace = 200 * time.Millisecond
	return h
}

// connect robi ofertę dla sesji i zgłasza połączenie widza, tak jak robi to pomocnik.
func (h *elevHarness) connect(t *testing.T, session string) *fakeProc {
	t.Helper()
	if _, err := h.e.Signal(context.Background(), session, offerSig(session)); err != nil {
		t.Fatal(err)
	}
	p := h.procs.at(h.procs.count() - 1)
	p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopState, SessionID: session, State: ipc.StateConnected}
	waitUntil(t, "połączenie widza", func() bool { ok, _ := h.e.Connected(context.Background()); return ok })
	return p
}

func (h *elevHarness) request(session, engineer string) ElevationRequest {
	return ElevationRequest{SessionID: session, RequestID: "req-" + session, Engineer: engineer, Login: "jan@example.test", Tenant: "Kancelaria Lis"}
}

// elevate pyta o zgodę (jak runner po remote.elevate).
func (h *elevHarness) elevate(session, engineer string) ElevationOutcome {
	out, _ := h.e.Elevate(context.Background(), h.request(session, engineer))
	return out
}

// elevateAndConfirm to zgoda użytkownika i potwierdzenie serwera (jak runner po remote.elevation.ack).
func (h *elevHarness) elevateAndConfirm(t *testing.T, session, engineer string) ElevationOutcome {
	t.Helper()
	out := h.elevate(session, engineer)
	if out.State == wire.ElevationGranted {
		if err := h.e.ActivateElevation(session); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("nie doczekano: %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func hasKind(p *fakeProc, k ipc.DesktopKind) bool {
	for _, got := range p.kinds() {
		if got == k {
			return true
		}
	}
	return false
}

func TestElevateGrantedRestartsHelperAtIntegrityOnlyAfterServerConfirmation(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	first := h.connect(t, "s1")

	out := h.elevate("s1", "Jan Kowalski")
	if out.State != wire.ElevationGranted {
		t.Fatalf("wynik: %+v", out)
	}
	req := h.consent.request()
	if h.consent.count() != 1 || req.Engineer != "Jan Kowalski" || req.Login != "jan@example.test" || req.Tenant != "Kancelaria Lis" {
		t.Fatalf("okno zgody dostało: pytań %d, %+v", h.consent.count(), req)
	}
	// Zgoda użytkownika to jeszcze NIE podniesienie: pomocnik działa, wejście od widza zostaje wstrzymane do potwierdzenia serwera, a karta
	// komputera nie mówi o podniesieniu.
	if hasKind(first, ipc.DesktopStop) || first.wasKilled() {
		t.Fatal("przed potwierdzeniem serwera pomocnik nie może być zatrzymany")
	}
	if !hasKind(first, ipc.DesktopPause) || hasKind(first, ipc.DesktopResume) {
		t.Fatalf("wejście ma być wstrzymane na czas oczekiwania na potwierdzenie: %v", first.kinds())
	}
	if st := h.e.HelperStatus(); st.SessionLevel != "" || st.Level != config.DesktopHelperUser {
		t.Fatalf("stan przed potwierdzeniem: %+v", st)
	}

	// Potwierdzenie serwera: stary pomocnik zatrzymany łagodnie, sesja trzymana jako połączona, karta pokazuje podniesienie na czas sesji.
	if err := h.e.ActivateElevation("s1"); err != nil {
		t.Fatal(err)
	}
	kinds := first.kinds()
	if kinds[len(kinds)-1] != ipc.DesktopStop {
		t.Fatalf("stary pomocnik powinien dostać stop: %v", kinds)
	}
	if ok, _ := h.e.Connected(context.Background()); !ok {
		t.Fatal("po zgodzie sesja ma pozostać połączona do ponownego połączenia widza")
	}
	if st := h.e.HelperStatus(); st.SessionLevel != config.DesktopHelperIntegrity || st.Level != config.DesktopHelperUser {
		t.Fatalf("w podniesionej sesji karta ma pokazać poziom sesji, a stały poziom komputera zostaje user: %+v", st)
	}

	// Ponowna oferta tej samej sesji startuje pomocnika na poziomie integrity, a start trafia do audytu z rodzajem tokenu.
	second := h.connect(t, "s1")
	if second == first {
		t.Fatal("po zgodzie powinien powstać nowy pomocnik")
	}
	if got := h.launchedLevels(); len(got) != 2 || got[0] != config.DesktopHelperUser || got[1] != config.DesktopHelperIntegrity {
		t.Fatalf("poziomy startów: %v", got)
	}
	reports := h.startReports()
	if len(reports) != 2 || reports[0].byRequest || reports[0].choice.Kind != TokenUserRequested || !reports[1].byRequest || reports[1].choice.Kind != TokenIntegrity || reports[1].level != config.DesktopHelperUser {
		t.Fatalf("zgłoszenia startów (osobny wpis audytu przy każdym starcie): %+v", reports)
	}
	// Druga prośba w tej samej sesji: już podwyższone, bez ponownego pytania.
	if out := h.elevate("s1", "Jan Kowalski"); out.State != wire.ElevationAlready || h.consent.count() != 1 {
		t.Fatalf("druga prośba: %+v, pytań %d", out, h.consent.count())
	}

	// Koniec sesji kasuje zgodę: kolejna sesja startuje znowu jako zwykły użytkownik i pyta od nowa.
	h.e.EndSession(context.Background())
	if st := h.e.HelperStatus(); st.SessionLevel != "" {
		t.Fatalf("po końcu sesji karta nie pokazuje już podniesienia: %+v", st)
	}
	h.connect(t, "s2")
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
		t.Fatalf("nowa sesja nie może dziedziczyć zgody: %v", got)
	}
	if out := h.elevateAndConfirm(t, "s2", "Jan Kowalski"); out.State != wire.ElevationGranted || h.consent.count() != 2 {
		t.Fatalf("nowa sesja pyta od nowa: %+v, pytań %d", out, h.consent.count())
	}
	// Zgoda jest przypisana do sesji s2, nie do poprzedniej: oferta s1 nie dostaje integrity.
	if _, err := h.e.Signal(context.Background(), "s1", offerSig("s1")); err != nil {
		t.Fatal(err)
	}
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
		t.Fatalf("zgoda s2 nie dotyczy s1: %v", got)
	}
}

func TestElevationWithoutServerConfirmationIsCancelledAndNothingIsRaised(t *testing.T) {
	// Zgoda użytkownika, a potwierdzenia serwera nie ma (zerwane połączenie, prośba wygasła, serwer odrzucił): wejście wraca, poziom bez zmian.
	h := newElevHarness(t, config.DesktopHelperUser)
	p := h.connect(t, "s1")
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationGranted {
		t.Fatalf("%+v", out)
	}
	h.e.CancelElevation("s1")
	if !hasKind(p, ipc.DesktopResume) || hasKind(p, ipc.DesktopStop) || p.wasKilled() {
		t.Fatalf("po anulowaniu wejście wraca, a pomocnik zostaje: %v", p.kinds())
	}
	if err := h.e.ActivateElevation("s1"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("anulowana zgoda nie może być już aktywowana: %v", err)
	}
	if st := h.e.HelperStatus(); st.SessionLevel != "" {
		t.Fatalf("nic nie podniesiono: %+v", st)
	}
	h.connect(t, "s1")
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
		t.Fatalf("po anulowaniu kolejna oferta startuje jako user: %v", got)
	}

	// Sama zgoda sama się anuluje po GrantTTL, a oferta widza nie czeka na nią w nieskończoność.
	h2 := newElevHarness(t, config.DesktopHelperUser)
	h2.e.GrantTTL = 80 * time.Millisecond
	p2 := h2.connect(t, "s1")
	if out := h2.elevate("s1", "Jan"); out.State != wire.ElevationGranted {
		t.Fatalf("%+v", out)
	}
	waitUntil(t, "automatyczne anulowanie po GrantTTL", func() bool { return hasKind(p2, ipc.DesktopResume) })
	if err := h2.e.ActivateElevation("s1"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("po GrantTTL nie ma czego aktywować: %v", err)
	}
	// Koniec sesji też anuluje zgodę, która czeka.
	h3 := newElevHarness(t, config.DesktopHelperUser)
	h3.connect(t, "s1")
	h3.elevate("s1", "Jan")
	h3.e.EndSession(context.Background())
	if err := h3.e.ActivateElevation("s1"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("zgoda nie przeżywa końca sesji: %v", err)
	}
}

func TestOfferRightAfterConsentWaitsForTheServerConfirmationInsteadOfStartingAtOldLevel(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.connect(t, "s1")
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationGranted {
		t.Fatalf("%+v", out)
	}
	done := make(chan error, 1)
	go func() {
		_, err := h.e.Signal(context.Background(), "s1", offerSig("s1"))
		done <- err
	}()
	select {
	case <-done:
		t.Fatal("oferta wysłana tuż po zgodzie nie może wystartować pomocnika przed rozstrzygnięciem zgody")
	case <-time.After(150 * time.Millisecond):
	}
	if err := h.e.ActivateElevation("s1"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperIntegrity {
		t.Fatalf("oferta po potwierdzeniu startuje na integrity: %v", got)
	}
}

func TestElevateDeniedOrTimedOutResumesInputAndKeepsHelperAndLevel(t *testing.T) {
	for _, c := range []struct {
		name     string
		decision ConsentDecision
		state    string
	}{
		{"odmowa", ConsentDenied, wire.ElevationDenied},
		{"brak odpowiedzi", ConsentTimedOut, wire.ElevationTimeout},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newElevHarness(t, config.DesktopHelperUser)
			h.consent.decision = c.decision
			p := h.connect(t, "s1")
			// Wejście od widza jest wstrzymane już w chwili pokazania okna zgody (inżynier nie kliknie w nic obok okna).
			paused := false
			h.consent.onAsk = func() { paused = hasKind(p, ipc.DesktopPause) && !hasKind(p, ipc.DesktopResume) }
			out := h.elevate("s1", "Jan")
			if out.State != c.state || out.Reason == "" {
				t.Fatalf("wynik: %+v", out)
			}
			if !paused {
				t.Fatal("wejście ma być wstrzymane, zanim pojawi się okno zgody")
			}
			if !hasKind(p, ipc.DesktopResume) {
				t.Fatalf("po decyzji wejście wraca: %v", p.kinds())
			}
			if hasKind(p, ipc.DesktopStop) || p.wasKilled() {
				t.Fatal("po odmowie pomocnik nie może być zatrzymany")
			}
			// Dalsza oferta tej samej sesji nadal startuje jako zwykły użytkownik.
			if _, err := h.e.Signal(context.Background(), "s1", offerSig("s1")); err != nil {
				t.Fatal(err)
			}
			if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
				t.Fatalf("poziomy startów: %v", got)
			}
			// Po odmowie można poprosić jeszcze raz (decyzja o limitach i odstępach należy do silnika i serwera).
			h.consent.decision = ConsentAllowed
			h.connect(t, "s1")
			if out := h.elevateAndConfirm(t, "s1", "Jan"); out.State != wire.ElevationGranted {
				t.Fatalf("po odmowie ponowna prośba: %+v", out)
			}
		})
	}
}

func TestElevateRefusesWithoutAskingWhenNotApplicable(t *testing.T) {
	// Stały poziom komputera podwyższony: nie ma o co pytać.
	for _, level := range []string{config.DesktopHelperIntegrity, config.DesktopHelperAdmin} {
		h := newElevHarness(t, level)
		h.connect(t, "s1")
		if out := h.elevate("s1", "Jan"); out.State != wire.ElevationAlready || h.consent.count() != 0 {
			t.Fatalf("poziom %s: %+v, pytań %d", level, out, h.consent.count())
		}
	}

	h := newElevHarness(t, "") // pusty = user
	// Brak sesji / inna sesja.
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationError {
		t.Fatalf("bez sesji: %+v", out)
	}
	h.connect(t, "s1")
	if out := h.elevate("inna", "Jan"); out.State != wire.ElevationError || h.consent.count() != 0 {
		t.Fatalf("cudza sesja: %+v, pytań %d", out, h.consent.count())
	}
	// Agent poza usługą: nie ma jak zapytać użytkownika.
	h.e.CanElevate = func() bool { return false }
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationUnavailable || h.consent.count() != 0 {
		t.Fatalf("bez usługi: %+v, pytań %d", out, h.consent.count())
	}
	// Nikt nie jest zalogowany / okno się nie pokazało: niedostępne, bez podnoszenia, a wejście wraca.
	h.e.CanElevate = func() bool { return true }
	h.consent.err = ErrNoUserSession
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationUnavailable {
		t.Fatalf("bez użytkownika: %+v", out)
	}
	h.consent.err = errors.New("CreateProcessAsUser: odmowa")
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationUnavailable || !strings.Contains(out.Reason, "CreateProcessAsUser") {
		t.Fatalf("błąd okna: %+v", out)
	}
	p := h.procs.at(h.procs.count() - 1)
	if hasKind(p, ipc.DesktopStop) || len(h.launchedLevels()) != 1 {
		t.Fatalf("nic nie powinno restartować pomocnika: %v %v", p.kinds(), h.launchedLevels())
	}
}

func TestElevateIsUnavailableWhenUACIsOffAndReportsIt(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.connect(t, "s1")
	if st := h.e.HelperStatus(); st.UAC != "on" {
		t.Fatalf("UAC włączony: %+v", st)
	}
	h.e.UACOff = func() bool { return true } // EnableLUA=0
	out := h.elevate("s1", "Jan")
	if out.State != wire.ElevationUnavailable || !strings.Contains(out.Reason, "UAC") || h.consent.count() != 0 {
		t.Fatalf("UAC wyłączony: %+v, pytań %d", out, h.consent.count())
	}
	if st := h.e.HelperStatus(); st.UAC != "off" {
		t.Fatalf("UAC wyłączony ma być zgłoszony: %+v", st)
	}
	// Użytkownik z pełnym tokenem (typ Full, np. wbudowany administrator) też znaczy brak filtrowania.
	h2 := newElevHarness(t, config.DesktopHelperUser)
	h2.connect(t, "s1")
	h2.e.recordChoice(TokenChoice{Kind: TokenUserRequested, Elevation: "full"})
	if out := h2.elevate("s1", "Jan"); out.State != wire.ElevationUnavailable || h2.consent.count() != 0 {
		t.Fatalf("token typu full: %+v", out)
	}
	// Agent, który nie umie sprawdzić UAC, nie zgłasza nic.
	h3 := newElevHarness(t, config.DesktopHelperUser)
	h3.e.UACOff = nil
	if st := h3.e.HelperStatus(); st.UAC != "" {
		t.Fatalf("nieznany stan UAC: %+v", st)
	}
}

func TestElevateOnePromptAtATimeAndSessionEndCancelsIt(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.consent.release = make(chan struct{})
	p := h.connect(t, "s1")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan ElevationOutcome, 1)
	go func() { out, _ := h.e.Elevate(ctx, h.request("s1", "Jan")); done <- out }()
	waitUntil(t, "okno zgody pokazane", func() bool { return h.consent.count() == 1 })

	// Druga prośba w trakcie pierwszej nie pokazuje drugiego okna.
	if out := h.elevate("s1", "Jan"); out.State != wire.ElevationError || h.consent.count() != 1 {
		t.Fatalf("równoległa prośba: %+v, pytań %d", out, h.consent.count())
	}
	// Koniec sesji w trakcie pytania: żadnego podniesienia.
	cancel()
	select {
	case out := <-done:
		if out.State != wire.ElevationError {
			t.Fatalf("po zakończeniu sesji: %+v", out)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("prośba nie skończyła się po zakończeniu sesji")
	}
	if got := h.launchedLevels(); len(got) != 1 {
		t.Fatalf("pomocnik nie powinien być restartowany: %v", got)
	}
	_ = p
}

func TestElevateGrantedForVanishedSessionDoesNothing(t *testing.T) {
	// Użytkownik zezwolił, ale inżynier w międzyczasie zamknął sesję: zgoda nie może przeżyć sesji.
	h := newElevHarness(t, config.DesktopHelperUser)
	h.consent.release = make(chan struct{})
	h.connect(t, "s1")
	done := make(chan ElevationOutcome, 1)
	go func() { done <- h.elevate("s1", "Jan") }()
	waitUntil(t, "okno zgody", func() bool { return h.consent.count() == 1 })
	h.e.EndSession(context.Background())
	close(h.consent.release) // użytkownik klika „Tak” po końcu sesji
	out := <-done
	if out.State == wire.ElevationGranted {
		t.Fatalf("zgoda po końcu sesji nie może zostać przyjęta: %+v", out)
	}
	if err := h.e.ActivateElevation("s1"); !errors.Is(err, ErrNoGrant) {
		t.Fatalf("nie ma czego aktywować: %v", err)
	}
	h.connect(t, "s1")
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
		t.Fatalf("zgoda po końcu sesji nie może podnosić kolejnej oferty: %v", got)
	}
}

func TestElevationHoldExpiresWhenViewerNeverReconnects(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.e.ReconnectWindow = 80 * time.Millisecond
	h.connect(t, "s1")
	if out := h.elevateAndConfirm(t, "s1", "Jan"); out.State != wire.ElevationGranted {
		t.Fatalf("%+v", out)
	}
	if ok, _ := h.e.Connected(context.Background()); !ok {
		t.Fatal("w oknie ponownego połączenia sesja trwa")
	}
	time.Sleep(150 * time.Millisecond)
	if ok, _ := h.e.Connected(context.Background()); ok {
		t.Fatal("po upływie okna bez ponownego połączenia sesja ma się rozłączyć (Manager ją zamknie)")
	}
}

// Manager zamyka sesję, gdy po zgodzie widz nie połączył się ponownie w oknie wstrzymania: EndSession zeruje zgodę (poziom sesji znika z karty),
// a serwer dostaje stan „rozłączono”; kolejna sesja startuje jako user.
func TestManagerClosesSessionWhenViewerNeverReconnectsAndClearsTheGrant(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.e.ReconnectWindow = 60 * time.Millisecond
	var mu sync.Mutex
	var states []string
	mgr := NewManager(Options{Module: h.e, Log: quietLog(), Emit: func(sessionID, state string, _ *wire.RemoteStats) {
		mu.Lock()
		states = append(states, sessionID+":"+state)
		mu.Unlock()
	}, Poll: time.Hour})
	ctx := context.Background()
	if _, err := mgr.Open(ctx, "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Signal(ctx, "s1", offerSig("s1")); err != nil {
		t.Fatal(err)
	}
	h.procs.at(0).msgs <- ipc.DesktopMsg{Kind: ipc.DesktopState, SessionID: "s1", State: ipc.StateConnected}
	waitUntil(t, "połączenie widza", func() bool { ok, _ := h.e.Connected(ctx); return ok })
	mgr.Tick(ctx) // Manager notuje połączenie

	out, err := mgr.Elevate(ctx, h.request("s1", "Jan"))
	if err != nil || out.State != wire.ElevationGranted {
		t.Fatalf("%+v %v", out, err)
	}
	if err := mgr.ActivateElevation("s1"); err != nil {
		t.Fatal(err)
	}
	mgr.Tick(ctx) // w oknie ponownego połączenia sesja trwa
	if _, ok := mgr.Active(); !ok {
		t.Fatal("sesja trwa w oknie ponownego połączenia")
	}
	time.Sleep(120 * time.Millisecond)
	mgr.Tick(ctx) // okno minęło, widz nie wrócił
	if _, ok := mgr.Active(); ok {
		t.Fatal("Manager ma zamknąć sesję po oknie ponownego połączenia")
	}
	mu.Lock()
	got := strings.Join(states, ",")
	mu.Unlock()
	if !strings.Contains(got, "s1:"+StateDisconnected) {
		t.Fatalf("serwer ma dostać stan rozłączono: %q", got)
	}
	if st := h.e.HelperStatus(); st.SessionLevel != "" {
		t.Fatalf("EndSession ma wyzerować zgodę: %+v", st)
	}
	if _, err := mgr.Open(ctx, "s2", time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := mgr.Signal(ctx, "s2", offerSig("s2")); err != nil {
		t.Fatal(err)
	}
	if got := h.launchedLevels(); got[len(got)-1] != config.DesktopHelperUser {
		t.Fatalf("kolejna sesja startuje jako user: %v", got)
	}
}

// Restart agenta w podniesionej sesji: zgoda żyje tylko w pamięci procesu, więc nowy proces wraca do „user” także dla tej samej sesji.
func TestAgentRestartInElevatedSessionFallsBackToUser(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.connect(t, "s1")
	h.elevateAndConfirm(t, "s1", "Jan")
	if got := h.e.launchLevelFor("s1"); got != config.DesktopHelperIntegrity {
		t.Fatalf("przed restartem: %q", got)
	}
	restarted := newElevHarness(t, config.DesktopHelperUser)
	if got := restarted.e.launchLevelFor("s1"); got != config.DesktopHelperUser {
		t.Fatalf("po restarcie agenta ta sama sesja wraca do user: %q", got)
	}
	restarted.connect(t, "s1")
	if got := restarted.launchedLevels(); got[0] != config.DesktopHelperUser {
		t.Fatalf("%v", got)
	}
}

// Stary pomocnik, który nie reaguje na stop, jest zabijany po StopGrace i nie zostaje osierocony; nowy powstaje dopiero z oferty widza.
func TestSlowStoppingOldHelperIsKilledNotOrphaned(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.procs = &procList{}
	e := h.e
	slow := func() *fakeProc {
		p := newFakeProc()
		p.autoReady, p.autoAnswer = true, true // closeOnStop = false: ignoruje stop
		return p
	}
	inner := func(context.Context, string, *slog.Logger) (Process, error) {
		p := slow()
		h.procs.add(p)
		p.msgs <- ipc.DesktopMsg{Kind: ipc.DesktopReady, Displays: []ipc.DesktopDisplay{{Index: 0, Width: 1, Height: 1}}}
		return p, nil
	}
	e.Launch = func(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
		h.mu.Lock()
		h.levels = append(h.levels, e.launchLevel())
		h.mu.Unlock()
		return inner(ctx, exe, log)
	}
	first := h.connect(t, "s1")
	h.elevate("s1", "Jan")
	start := time.Now()
	if err := e.ActivateElevation("s1"); err != nil {
		t.Fatal(err)
	}
	if !first.wasKilled() {
		t.Fatal("pomocnik, który nie reaguje na stop, musi zostać zabity po StopGrace")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("zatrzymanie trwało %v", time.Since(start))
	}
	second := h.connect(t, "s1")
	if second == first || second.wasKilled() || h.procs.count() != 2 {
		t.Fatalf("nowy pomocnik powstaje z oferty widza, stary nie wraca: procesów %d", h.procs.count())
	}
}

func TestOnHelperStartIsNotCalledWithoutTokenChoiceAndPromptLimitsSurviveSessions(t *testing.T) {
	// W trybie rozwojowym (bez usługi) nie ma wyboru tokenu, więc nie ma czego zgłaszać do audytu.
	e, _ := newTestEngine(t, readyAnswering)
	called := false
	e.OnHelperStart = func(string, TokenChoice, string, bool) { called = true }
	if _, err := e.Signal(context.Background(), "s1", offerSig("s1")); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("bez wyboru tokenu nie zgłaszamy startu")
	}
}

func TestElevationPromptLimitsPerSessionPerHourAndGap(t *testing.T) {
	h := newElevHarness(t, config.DesktopHelperUser)
	h.consent.decision = ConsentDenied
	h.connect(t, "s1")
	for i := 0; i < maxElevationPrompts; i++ {
		if out := h.elevate("s1", "Jan"); out.State != wire.ElevationDenied {
			t.Fatalf("prośba %d: %+v", i+1, out)
		}
	}
	out := h.elevate("s1", "Jan")
	if out.State != wire.ElevationError || h.consent.count() != maxElevationPrompts {
		t.Fatalf("po limicie sesji okno nie może się już pokazać: %+v, pytań %d", out, h.consent.count())
	}

	// Limit godzinowy liczy okna niezależnie od sesji: koniec sesji go NIE zeruje.
	h.e.EndSession(context.Background())
	h.connect(t, "s2")
	for i := 0; i < maxElevationPrompts; i++ {
		if out := h.elevate("s2", "Jan"); out.State != wire.ElevationDenied {
			t.Fatalf("s2 prośba %d: %+v", i+1, out)
		}
	}
	if h.consent.count() != 2*maxElevationPrompts || maxElevationPromptsPerHour != 2*maxElevationPrompts {
		t.Fatalf("założenie testu: %d okien, limit godzinowy %d", h.consent.count(), maxElevationPromptsPerHour)
	}
	h.e.EndSession(context.Background())
	h.connect(t, "s3")
	out = h.elevate("s3", "Jan")
	if out.State != wire.ElevationError || !strings.Contains(out.Reason, "godziny") || h.consent.count() != maxElevationPromptsPerHour {
		t.Fatalf("limit godzinowy: %+v, pytań %d", out, h.consent.count())
	}

	// Odstęp od poprzedniego okna: kolejne okno tuż po odmowie nie pojawia się seryjnie (domyślny odstęp).
	g := newElevHarness(t, config.DesktopHelperUser)
	g.e.PromptGap = 0 // domyślne 10 s
	g.consent.decision = ConsentDenied
	g.connect(t, "s1")
	if out := g.elevate("s1", "Jan"); out.State != wire.ElevationDenied {
		t.Fatalf("%+v", out)
	}
	out = g.elevate("s1", "Jan")
	if out.State != wire.ElevationError || !strings.Contains(out.Reason, "poczekaj") || g.consent.count() != 1 {
		t.Fatalf("odstęp między oknami: %+v, pytań %d", out, g.consent.count())
	}
}

func TestPlainLabelAndConsentTextKeepServerDataInLabelledLines(t *testing.T) {
	cases := map[string]string{
		"Jan Kowalski":                  "Jan Kowalski",
		"  Jan \n\t Kowalski  ":         "Jan Kowalski",
		"Jan\r\nSystem: kliknij Tak":    "Jan System kliknij Tak",
		"A\u202Eevil\u202C":             "A evil",
		"„Tak = zezwalam”":              "Tak zezwalam",
		"Jan (admin) <b>x</b>":          "Jan admin bxb",
		"":                              "",
		"\x00\x01\x02":                  "",
		"\u200B\u200D":                  "",
		strings.Repeat("ą", 200):        strings.Repeat("ą", 60) + "…",
		"jan.kowalski+test@exa-mple.pl": "jan.kowalski+test@exa-mple.pl",
		"Jan\u2028Kowalski":             "Jan Kowalski",
		"Piotr Nowak, Biuro & Spółka":   "Piotr Nowak, Biuro & Spółka",
		"Zażółć gęślą jaźń":             "Zażółć gęślą jaźń",
		"'; DROP TABLE users; --":       "DROP TABLE users --",
	}
	for in, want := range cases {
		if got := plainLabel(in, maxLabelRunes); got != want {
			t.Errorf("plainLabel(%q) = %q, oczekiwano %q", in, got, want)
		}
	}

	req := ConsentRequest{Engineer: "Jan\nTak = zezwalam \"x\"", Login: "jan@example.test", Tenant: "Kancelaria „Lis”\n", Timeout: ConsentTimeout}
	text := consentText(req)
	for _, must := range []string{"\nInżynier: jan@example.test (Jan Tak zezwalam x)\n", "\nFirma: Kancelaria Lis\n", "administrator", "Tak = zezwalam (tylko na czas tej sesji)", "Nie = odmawiam", "60 sekund", "wygasa wraz z końcem sesji"} {
		if !strings.Contains(text, must) {
			t.Errorf("treść okna zgody nie zawiera %q:\n%s", must, text)
		}
	}
	// Dane z serwera nie dokładają linii ani cudzysłowów: układ okna jest stały, więc nie da się udać dalszej części komunikatu.
	plain := consentText(ConsentRequest{Engineer: "Jan", Login: "jan@example.test", Tenant: "Kancelaria Lis", Timeout: ConsentTimeout})
	if strings.Count(text, "\n") != strings.Count(plain, "\n") || strings.ContainsAny(text, "„”\"") {
		t.Errorf("dane z serwera zmieniły układ albo dodały cudzysłowy:\n%s", text)
	}
	// Bez loginu i firmy: sama nazwa, bez linii „Firma:”; bez niczego: jawne „brak danych”.
	if txt := consentText(ConsentRequest{Engineer: "Jan Kowalski"}); !strings.Contains(txt, "Inżynier: Jan Kowalski\n") || strings.Contains(txt, "Firma:") {
		t.Errorf("sama nazwa:\n%s", txt)
	}
	if txt := consentText(ConsentRequest{}); !strings.Contains(txt, "Inżynier: brak danych\n") {
		t.Errorf("brak danych:\n%s", txt)
	}
	// Okno nie obiecuje twardej ochrony.
	for _, forbidden := range []string{"chroni", "bezpiecz", "gwarant"} {
		if strings.Contains(strings.ToLower(text), forbidden) {
			t.Errorf("treść okna zgody nie powinna sugerować twardej ochrony (%q):\n%s", forbidden, text)
		}
	}
}
