package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// HelperExeName to nazwa pliku pomocnika pulpitu obok agent.exe w katalogu programu.
const HelperExeName = "desktop-helper.exe"

// helperManifestName to plik boczny z wersją i skrótem zainstalowanego pomocnika (zapisywany przy instalacji komponentu).
const helperManifestName = "desktop-helper.json"

// Czasy oczekiwania na pomocnika. stopGrace musi być dłuższy niż czekanie pomocnika na własny silnik (3 s), żeby zdążył
// puścić klawisze i zamknąć połączenie, zanim usługa go zabije.
const (
	readyTimeout  = 15 * time.Second
	answerTimeout = 20 * time.Second
	stopGrace     = 5 * time.Second
)

// Błędy własnego silnika.
var (
	// ErrNoSignaling: moduł pulpitu nie obsługuje sygnalizacji WebRTC (RustDesk).
	ErrNoSignaling = errors.New("remote: moduł pulpitu nie obsługuje sygnalizacji WebRTC")
	// ErrNoUserSession: nikt nie jest zalogowany na konsoli, więc pomocnika nie ma gdzie uruchomić (ekran logowania to etap 1b).
	ErrNoUserSession = errors.New("remote: brak zalogowanego użytkownika na konsoli")
	// ErrOfferInProgress: trwa obsługa innej oferty dla tego komputera.
	ErrOfferInProgress = errors.New("remote: trwa obsługa innej oferty")
	// ErrHelperUntrusted: plik pomocnika nie zgadza się ze skrótem zapisanym przy instalacji (albo nie był instalowany komponentem).
	ErrHelperUntrusted = errors.New("remote: pomocnik pulpitu nie przeszedł weryfikacji skrótu")
)

// Process to uruchomiony pomocnik: komunikaty w obie strony i zabicie. Messages zamyka się po końcu procesu.
type Process interface {
	Send(m ipc.DesktopMsg) error
	Messages() <-chan ipc.DesktopMsg
	Kill()
}

// helperManifest to zawartość pliku bocznego pomocnika.
type helperManifest struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// Engine to własny silnik pulpitu (WebRTC) jako implementacja Module: usługa jest płaszczyzną sterowania i audytu,
// a przechwytywanie, kodowanie i wstrzykiwanie robi osobny pomocnik w sesji użytkownika (docs/adr/0009, korekty po
// prototypie). Hasło jednorazowe z Managera nie jest używane: tożsamość widza potwierdza panel (sesja, step-up),
// a połączenie medialne pilnuje odcisk DTLS przypięty do sesji przez serwer i sprawdzany przez pomocnika.
type Engine struct {
	// Exe to ścieżka pomocnika (desktop-helper.exe).
	Exe string
	Log *slog.Logger
	// Launch uruchamia pomocnika; domyślnie w sesji zalogowanego użytkownika (usługa) albo jako zwykły proces potomny
	// (tryb rozwojowy bez usługi). Testy podstawiają atrapę.
	Launch func(ctx context.Context, exe string, log *slog.Logger) (Process, error)
	// HelperLevel to poziom uprawnień pomocnika (config.DesktopHelperUser | Integrity | Admin; pusty = user), ustawiany raz przy
	// starcie agenta. Pod usługą SYSTEM pomocnik dostaje: (integrity) zwykły token użytkownika z wysoką integralnością, bez grupy
	// Administratorzy; (admin) token administratora TEGO SAMEGO użytkownika; (user) token średniej integralności. Obniżenie poziomu
	// po nieudanym wyborze i odmowa startu przy podniesionym tokenie, którego nie da się odchudzić, opisuje chooseHelperToken.
	// Brak SYSTEM w żadnym wariancie.
	HelperLevel string
	// Consent pyta użytkownika na komputerze o zgodę na podniesienie uprawnień pomocnika w tej sesji. Domyślnie okno rysuje podproces
	// "desktop-helper consent" z tokenem o wysokiej integralności, więc UIPI chroni je przed zatwierdzeniem wstrzykniętym wejściem z
	// pomocnika (średnia integralność). Testy podstawiają atrapę.
	Consent func(ctx context.Context, req ConsentRequest) (ConsentDecision, error)
	// CanElevate mówi, czy da się zapytać użytkownika i uruchomić pomocnika wyżej (tylko pod usługą SYSTEM); domyślnie runningAsSystem.
	CanElevate func() bool
	// ReconnectWindow to czas trzymania sesji „połączonej” po zgodzie, na ponowne połączenie widza (domyślnie 90 s).
	ReconnectWindow time.Duration
	// GrantTTL to czas, w którym zgoda czeka na potwierdzenie serwera (domyślnie 30 s), zanim sama się anuluje.
	GrantTTL time.Duration
	// StopGrace to czas na łagodne zatrzymanie pomocnika przed zabiciem (domyślnie 5 s).
	StopGrace time.Duration
	// PromptGap to minimalny odstęp od końca poprzedniego okna zgody do następnego (domyślnie 10 s, wartość ujemna wyłącza odstęp w testach).
	PromptGap time.Duration
	// UACOff mówi, czy kontrola konta użytkownika jest wyłączona (EnableLUA=0); domyślnie odczyt z rejestru. Przy wyłączonym UAC poziom „user” nie
	// chroni okien administratora, więc prośba o zgodę nie ma sensu.
	UACOff func() bool
	// OnHelperStart dostaje zgłoszenie każdego startu pomocnika pod usługą (token, poziom komputera, czy poziom podniesiono na mocy zgody w tej sesji):
	// trafia do serwera jako remote.helper, do audytu rozbieżności.
	OnHelperStart func(sessionID string, c TokenChoice, level string, byRequest bool)
	// Verify sprawdza plik pomocnika przed każdym uruchomieniem. Domyślnie pod usługą (SYSTEM) porównuje skrót SHA-256
	// z plikiem bocznym zapisanym przy instalacji komponentu, a w trybie rozwojowym nic nie sprawdza. Usługa nigdy nie
	// uruchamia pomocnika na własnym koncie, więc podstawiony plik dostaje najwyżej uprawnienia zalogowanego użytkownika.
	Verify func(exe string) error
	// OnCandidate dostaje kandydatów ICE pomocnika zebranych po odpowiedzi (do przekazania widzowi przez serwer).
	OnCandidate func(sessionID, candidate, sdpMid string)
	// NoControl wyłącza sterowanie myszą i klawiaturą (tylko podgląd).
	NoControl bool

	exists func(string) bool

	// offerMu obejmuje całą obsługę oferty: druga oferta w trakcie pierwszej dostaje ErrOfferInProgress zamiast
	// wyścigu o e.cur i osieroconego pomocnika.
	offerMu sync.Mutex
	mu      sync.Mutex
	cur     *helperState
	// lastVersion to wersja z komunikatu ready ostatniego pomocnika (gdy brak pliku bocznego).
	lastVersion string
	// lastChoice to token z ostatniego startu pomocnika pod usługą (do raportu dla serwera); pusty przed pierwszym startem.
	lastChoice TokenChoice

	// Podniesienie uprawnień na czas jednej sesji (Elevate): elevatedSession to sesja, której pomocnik startuje na poziomie integrity;
	// holdSession/holdUntil trzymają sesję „połączoną” na czas ponownego połączenia widza; launchLvl to poziom bieżącego uruchomienia.
	elevMu          sync.Mutex
	elevatedSession string
	holdSession     string
	holdUntil       time.Time
	elevPrompts     int // ile razy w tej sesji pokazano okno zgody (zerowane przez EndSession)
	launchLvl       string
	// Zgoda udzielona przez użytkownika, a jeszcze niepotwierdzona przez serwer (pendingGrant = sesja), i historia okien zgody niezależna od sesji.
	pendingGrant  string
	grantDone     chan struct{}
	grantTimer    *time.Timer
	elevHist      []time.Time // kiedy w ostatniej godzinie pokazano okno zgody (NIE zerowane przez EndSession)
	lastPromptEnd time.Time
	choiceSeq     int // licznik wyborów tokenu (recordChoice): odróżnia start pod usługą od startu w trybie rozwojowym
}

type helperState struct {
	sessionID string
	proc      Process // nil do czasu uruchomienia
	connected bool
	ended     bool
	stats     *wire.RemoteStats
	answer    chan ipc.DesktopMsg
	done      chan struct{}
	displays  []ipc.DesktopDisplay
}

// NewEngine tworzy moduł własnego silnika z pomocnikiem w exe.
func NewEngine(exe string, log *slog.Logger) *Engine {
	if log == nil {
		log = slog.Default()
	}
	e := &Engine{
		Exe: exe, Log: log,
		exists: func(p string) bool { _, err := os.Stat(p); return err == nil },
	}
	e.Launch = func(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
		return launchHelper(ctx, exe, log, e.launchLevel(), e.recordChoice)
	}
	e.Consent = e.consentViaHelper
	e.CanElevate = runningAsSystem
	e.UACOff = uacDisabled
	e.Verify = e.defaultVerify
	return e
}

// recordChoice zapamiętuje, jaki token dostał ostatnio uruchomiony pomocnik.
func (e *Engine) recordChoice(c TokenChoice) {
	e.mu.Lock()
	e.lastChoice = c
	e.choiceSeq++
	e.mu.Unlock()
}

// HelperStatus (runner.HelperReporter) zwraca poziom uprawnień, z którym działa silnik od startu agenta, oraz rodzaj tokenu i
// zapas z ostatniego startu pomocnika.
func (e *Engine) HelperStatus() HelperStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := HelperStatus{Level: e.HelperLevel, Token: e.lastChoice.Kind, Fallback: e.lastChoice.Fallback, UAC: e.uacStateLocked()}
	if st.Level == "" {
		st.Level = config.DesktopHelperUser
	}
	// W sesji podniesionej na prośbę (zgoda użytkownika) karta komputera ma to pokazać, choć stały poziom komputera się nie zmienił.
	if e.elevatedSession != "" {
		st.SessionLevel = config.DesktopHelperIntegrity
	}
	return st
}

// uacOffLocked mówi, czy UAC jest wyłączony: wg rejestru albo dlatego, że użytkownik dostaje pełny token (typ Full). Wymaga trzymanego e.mu.
func (e *Engine) uacOffLocked() bool {
	if e.UACOff != nil && e.UACOff() {
		return true
	}
	return e.lastChoice.Elevation == "full"
}

// uacStateLocked to stan UAC do raportu: "off", "on" albo pusty tekst, gdy agent nie umie go sprawdzić.
func (e *Engine) uacStateLocked() string {
	switch {
	case e.uacOffLocked():
		return "off"
	case e.UACOff != nil:
		return "on"
	}
	return ""
}

// stopGrace zwraca czas na łagodne zatrzymanie pomocnika.
func (e *Engine) stopGrace() time.Duration {
	if e.StopGrace > 0 {
		return e.StopGrace
	}
	return stopGrace
}

// launchLevelFor zwraca poziom, z którym wystartuje pomocnik oferty tej sesji.
func (e *Engine) launchLevelFor(sessionID string) string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.launchLevelForLocked(sessionID)
}

func (e *Engine) launchLevelForLocked(sessionID string) string {
	if e.elevatedSession == sessionID {
		return config.DesktopHelperIntegrity
	}
	if e.HelperLevel == "" {
		return config.DesktopHelperUser
	}
	return e.HelperLevel
}

// launchLevel zwraca poziom, z którym ma wystartować pomocnik bieżącej oferty: stały poziom komputera, a dla sesji, w której
// użytkownik zezwolił na podniesienie, integrity.
func (e *Engine) launchLevel() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.launchLvl != "" {
		return e.launchLvl
	}
	return e.HelperLevel
}

// DefaultHelperExe to ścieżka pomocnika w katalogu programu (obok agent.exe).
func DefaultHelperExe() string {
	exe, err := os.Executable()
	if err != nil {
		return HelperExeName
	}
	return filepath.Join(filepath.Dir(exe), HelperExeName)
}

func (e *Engine) manifestPath() string { return filepath.Join(filepath.Dir(e.Exe), helperManifestName) }

func (e *Engine) readManifest() (helperManifest, error) {
	raw, err := os.ReadFile(e.manifestPath())
	if err != nil {
		return helperManifest{}, err
	}
	var m helperManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return helperManifest{}, err
	}
	return m, nil
}

// fileSHA256 liczy skrót pliku (szesnastkowo, małymi literami).
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// defaultVerify: pod usługą wymaga pliku bocznego i zgodnego skrótu; bez usługi (tryb rozwojowy, proces potomny na koncie
// dewelopera) niczego nie sprawdza.
func (e *Engine) defaultVerify(exe string) error {
	if !runningAsSystem() {
		return nil
	}
	return VerifyHelperHash(exe, e.manifestPath())
}

// VerifyHelperHash porównuje skrót pliku pomocnika z zapisanym w pliku bocznym.
func VerifyHelperHash(exe, manifest string) error {
	raw, err := os.ReadFile(manifest)
	if err != nil {
		return fmt.Errorf("%w: brak pliku bocznego: %v", ErrHelperUntrusted, err)
	}
	var m helperManifest
	if err := json.Unmarshal(raw, &m); err != nil || len(m.SHA256) != 64 {
		return fmt.Errorf("%w: zły plik boczny", ErrHelperUntrusted)
	}
	sum, err := fileSHA256(exe)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHelperUntrusted, err)
	}
	if !strings.EqualFold(sum, m.SHA256) {
		return ErrHelperUntrusted
	}
	return nil
}

// Engine (EngineNamer) nazywa silnik dla panelu.
func (e *Engine) Engine() string { return wire.RemoteEngineWebRTC }

// Installed mówi, czy pomocnik jest na miejscu.
func (e *Engine) Installed() bool { return e.exists(e.Exe) }

// ID zwraca stały identyfikator: adresem komputera jest sesja w panelu, nie numer jak w RustDesk.
func (e *Engine) ID(context.Context) (string, error) { return "webrtc", nil }

// SetPassword nic nie robi: dostęp otwiera i zamyka cykl życia pomocnika, nie hasło.
func (e *Engine) SetPassword(context.Context, string) error { return nil }

// EnsureConfig nic nie robi: pomocnik nie ma konfiguracji poza komunikatem start.
func (e *Engine) EnsureConfig(context.Context) error { return nil }

// Running mówi, czy moduł jest gotowy (pomocnik na miejscu).
func (e *Engine) Running(context.Context) bool { return e.Installed() }

// Connected mówi, czy widz jest połączony z pomocnikiem.
func (e *Engine) Connected(context.Context) (bool, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	// Po zgodzie na podniesienie uprawnień stary pomocnik jest zatrzymany, a widz łączy się z nowym: przez ReconnectWindow sesja
	// pozostaje połączona, żeby Manager nie uznał jej za rozłączoną.
	if e.holdSession != "" && time.Now().Before(e.holdUntil) {
		return true, nil
	}
	return e.cur != nil && e.cur.connected && !e.cur.ended, nil
}

// Version zwraca wersję pomocnika z pliku bocznego (zapisanego przy instalacji komponentu) albo z komunikatu ready
// ostatniego uruchomienia. Nigdy nie uruchamia pliku: usługa działa jako SYSTEM, a pomocnik ma działać tylko jako użytkownik.
func (e *Engine) Version(context.Context) string {
	if !e.Installed() {
		return ""
	}
	if m, err := e.readManifest(); err == nil && m.Version != "" {
		return m.Version
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastVersion
}

// Install (Installer) podmienia pomocnika na zweryfikowany plik ze staging bez znanej wersji (wywołujący powinien używać
// InstallVersion). Zapisuje plik boczny ze skrótem, żeby pod usługą dało się go uruchamiać.
func (e *Engine) Install(ctx context.Context, path string) error {
	return e.InstallVersion(ctx, path, "")
}

// InstallVersion (VersionedInstaller) podmienia pomocnika na zweryfikowany plik ze staging (komponent remote_module:
// podpis manifestu, suma SHA-256, Authenticode) atomowo przez plik tymczasowy i rename, a obok zapisuje wersję i skrót.
// W trakcie sesji Manager nie woła instalacji.
func (e *Engine) InstallVersion(_ context.Context, path, version string) error {
	if err := os.MkdirAll(filepath.Dir(e.Exe), 0o755); err != nil {
		return err
	}
	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()
	tmp := e.Exe + ".new"
	dst, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(dst, h), src); err != nil {
		dst.Close()
		os.Remove(tmp)
		return err
	}
	if err := dst.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	// Plik boczny przed podmianą: po udanym rename skrót już pasuje do nowego pliku, a stary pomocnik nie jest uruchamiany
	// w trakcie instalacji (Manager odrzuca instalację podczas sesji).
	manifest, err := json.Marshal(helperManifest{Version: version, SHA256: hex.EncodeToString(h.Sum(nil))})
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.WriteFile(e.manifestPath()+".new", manifest, 0o644); err != nil {
		os.Remove(tmp)
		return err
	}
	// Windows nie nadpisuje rename'em pliku, który ktoś trzyma; stary plik odkładamy na bok.
	_ = os.Remove(e.Exe + ".prev")
	_ = os.Rename(e.Exe, e.Exe+".prev")
	if err := os.Rename(tmp, e.Exe); err != nil {
		_ = os.Rename(e.Exe+".prev", e.Exe)
		_ = os.Remove(e.manifestPath() + ".new")
		return err
	}
	_ = os.Remove(e.manifestPath())
	return os.Rename(e.manifestPath()+".new", e.manifestPath())
}

// Signal (Signaler) obsługuje sygnalizację widza: oferta uruchamia pomocnika i zwraca jego odpowiedź z odciskiem DTLS,
// kandydat ICE idzie do działającego pomocnika (bez odpowiedzi). ctx powinien gasnąć razem z sesją w Managerze.
func (e *Engine) Signal(ctx context.Context, sessionID string, sig wire.RemoteSignal) (*wire.RemoteSignal, error) {
	switch sig.Kind {
	case wire.SignalOffer:
		return e.offer(ctx, sessionID, sig)
	case wire.SignalCandidate:
		e.mu.Lock()
		st := e.cur
		e.mu.Unlock()
		if st == nil || st.sessionID != sessionID || st.ended || st.proc == nil {
			return nil, ErrNoSession
		}
		return nil, st.proc.Send(ipc.DesktopMsg{Kind: ipc.DesktopSignal, SessionID: sessionID, Candidate: sig.Candidate, SDPMid: sig.SDPMid})
	}
	return nil, fmt.Errorf("remote: nieznany rodzaj sygnalizacji %q", sig.Kind)
}

func (e *Engine) offer(ctx context.Context, sessionID string, sig wire.RemoteSignal) (*wire.RemoteSignal, error) {
	if sig.SDP == "" {
		return nil, errors.New("remote: oferta bez SDP")
	}
	if sig.Fingerprint == "" {
		return nil, errors.New("remote: oferta bez odcisku DTLS widza")
	}
	if !e.Installed() {
		return nil, ErrNotInstalled
	}
	if !e.offerMu.TryLock() {
		return nil, ErrOfferInProgress
	}
	defer e.offerMu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.Verify != nil {
		if err := e.Verify(e.Exe); err != nil {
			return nil, err
		}
	}
	// Zgoda użytkownika czekająca na potwierdzenie serwera rozstrzyga się w ułamku sekundy: poczekaj, żeby oferta widza wysłana tuż po zgodzie
	// nie wystartowała pomocnika na starym poziomie.
	e.waitGrant(ctx, sessionID)
	// Nowa oferta zawsze zaczyna od świeżego pomocnika (ponowne połączenie widza po odświeżeniu strony albo po zgodzie na
	// podniesienie uprawnień). Zgoda na tę sesję przeżywa: kasuje ją dopiero EndSession (koniec sesji).
	e.endCurrent(ctx)
	e.mu.Lock()
	e.launchLvl = e.launchLevelForLocked(sessionID)
	e.mu.Unlock()

	// Stan sesji istnieje od razu (proc nil): EndSession w trakcie uruchamiania (remote.close, wygaśnięcie) zdejmie go
	// z e.cur, a my po Launch to zauważymy i zabijemy świeży proces zamiast zostawić go bez nadzoru.
	st := &helperState{sessionID: sessionID, answer: make(chan ipc.DesktopMsg, 1), done: make(chan struct{})}
	e.mu.Lock()
	e.cur = st
	e.mu.Unlock()

	e.mu.Lock()
	seqBefore := e.choiceSeq
	e.mu.Unlock()
	proc, err := e.Launch(ctx, e.Exe, e.Log)
	if err != nil {
		e.mu.Lock()
		if e.cur == st {
			e.cur = nil
		}
		e.mu.Unlock()
		close(st.done)
		return nil, fmt.Errorf("uruchomienie pomocnika pulpitu: %w", err)
	}
	e.mu.Lock()
	alive := e.cur == st && ctx.Err() == nil
	if alive {
		st.proc = proc
	}
	e.mu.Unlock()
	if !alive {
		proc.Kill()
		close(st.done)
		return nil, ErrNoSession
	}
	go e.pump(st)
	if e.OnHelperStart != nil {
		e.mu.Lock()
		choice, started := e.lastChoice, e.choiceSeq != seqBefore
		byRequest, stable := e.elevatedSession == sessionID, e.HelperLevel
		e.mu.Unlock()
		if started { // tylko start pod usługą (w trybie rozwojowym nie ma wyboru tokenu)
			if stable == "" {
				stable = config.DesktopHelperUser
			}
			e.OnHelperStart(sessionID, choice, stable, byRequest)
		}
	}

	fail := func(err error) (*wire.RemoteSignal, error) {
		e.endState(st)
		return nil, err
	}
	// Pomocnik zgłasza gotowość listą monitorów; dopiero wtedy dostaje ofertę.
	if err := e.waitReady(ctx, st); err != nil {
		return fail(err)
	}
	start := ipc.DesktopMsg{Kind: ipc.DesktopStart, SessionID: sessionID, SDP: sig.SDP, Fingerprint: sig.Fingerprint, ICEServers: sig.ICEServers, Control: !e.NoControl}
	if err := proc.Send(start); err != nil {
		return fail(fmt.Errorf("przekazanie oferty pomocnikowi: %w", err))
	}
	select {
	case m, ok := <-st.answer:
		if !ok || m.Kind != ipc.DesktopAnswer {
			if ok && m.Error != "" {
				return fail(fmt.Errorf("pomocnik pulpitu: %s", m.Error))
			}
			return fail(errors.New("pomocnik pulpitu zakończył się bez odpowiedzi"))
		}
		return &wire.RemoteSignal{SessionID: sessionID, Kind: wire.SignalAnswer, SDP: m.SDP, Fingerprint: m.Fingerprint}, nil
	case <-st.done:
		return fail(errors.New("pomocnik pulpitu zakończył się przed odpowiedzią"))
	case <-time.After(answerTimeout):
		return fail(errors.New("pomocnik pulpitu nie odpowiedział w czasie"))
	case <-ctx.Done():
		return fail(ctx.Err())
	}
}

func (e *Engine) waitReady(ctx context.Context, st *helperState) error {
	deadline := time.After(readyTimeout)
	for {
		e.mu.Lock()
		ready := st.displays != nil
		e.mu.Unlock()
		if ready {
			return nil
		}
		select {
		case <-st.done:
			return errors.New("pomocnik pulpitu zakończył się przed zgłoszeniem gotowości")
		case <-deadline:
			return errors.New("pomocnik pulpitu nie zgłosił gotowości w czasie")
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// pump czyta komunikaty pomocnika do zamknięcia kanału.
func (e *Engine) pump(st *helperState) {
	defer close(st.done)
	for m := range st.proc.Messages() {
		switch m.Kind {
		case ipc.DesktopReady:
			e.mu.Lock()
			st.displays = m.Displays
			if st.displays == nil {
				st.displays = []ipc.DesktopDisplay{}
			}
			if m.Version != "" {
				e.lastVersion = m.Version
			}
			e.mu.Unlock()
			e.Log.Info("pomocnik pulpitu gotowy", "version", m.Version, "displays", len(m.Displays))
		case ipc.DesktopAnswer:
			select {
			case st.answer <- m:
			default:
			}
		case ipc.DesktopCandidate:
			if e.OnCandidate != nil {
				e.OnCandidate(st.sessionID, m.Candidate, m.SDPMid)
			}
		case ipc.DesktopState:
			e.mu.Lock()
			switch m.State {
			case ipc.StateConnected:
				st.connected = true
				if e.holdSession == st.sessionID {
					e.holdSession = "" // widz połączył się z nowym pomocnikiem
				}
			case ipc.StateDisconnected, ipc.StateFailed:
				st.connected = false
				st.ended = true
				if m.Stats != nil {
					st.stats = m.Stats
				}
			}
			e.mu.Unlock()
			if m.State == ipc.StateFailed {
				e.Log.Warn("pomocnik pulpitu zgłosił błąd", "err", m.Error)
				select {
				case st.answer <- m: // oferta czekająca na odpowiedź dostaje błąd zamiast czekać do końca limitu
				default:
				}
			} else {
				e.Log.Info("stan sesji pulpitu", "state", m.State)
			}
		case ipc.DesktopLog:
			e.Log.Log(context.Background(), levelOf(m.Level), "pomocnik: "+m.Text)
		}
	}
	e.mu.Lock()
	st.connected = false
	st.ended = true
	e.mu.Unlock()
}

func levelOf(s string) slog.Level {
	switch strings.ToUpper(s) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	}
	return slog.LevelInfo
}

// EndSession (SessionEnder) kończy bieżącego pomocnika: prosi o zatrzymanie, po chwili zabija. Zwraca statystyki sesji,
// jeśli pomocnik je zgłosił.
func (e *Engine) EndSession(ctx context.Context) *wire.RemoteStats {
	// Koniec sesji: zgoda na podniesienie uprawnień wygasa razem z nią.
	e.mu.Lock()
	e.elevatedSession, e.holdSession, e.holdUntil, e.launchLvl, e.elevPrompts = "", "", time.Time{}, "", 0
	e.clearGrantLocked() // zgoda czekająca na potwierdzenie nie przeżyje sesji (okno zgody w historii zostaje: limit godzinowy jest niezależny od sesji)
	e.mu.Unlock()
	return e.endCurrent(ctx)
}

// endCurrent zatrzymuje bieżącego pomocnika, nie ruszając zgody na podniesienie uprawnień (wołane przy nowej ofercie tej samej sesji).
func (e *Engine) endCurrent(context.Context) *wire.RemoteStats {
	e.mu.Lock()
	st := e.cur
	e.cur = nil
	e.mu.Unlock()
	if st == nil {
		return nil
	}
	return e.endState(st)
}

// endState zatrzymuje konkretny stan pomocnika (także taki, który już nie jest e.cur).
func (e *Engine) endState(st *helperState) *wire.RemoteStats {
	e.mu.Lock()
	if e.cur == st {
		e.cur = nil
	}
	proc := st.proc
	e.mu.Unlock()
	if proc == nil {
		// Pomocnik jeszcze nie wystartował: offer() zobaczy, że e.cur != st, i zabije proces po Launch.
		return nil
	}
	_ = proc.Send(ipc.DesktopMsg{Kind: ipc.DesktopStop, SessionID: st.sessionID})
	select {
	case <-st.done:
	case <-time.After(e.stopGrace()):
		proc.Kill()
		select {
		case <-st.done:
		case <-time.After(e.stopGrace()):
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return st.stats
}

// Displays zwraca monitory zgłoszone przez działającego pomocnika (do wyboru w panelu).
func (e *Engine) Displays() []ipc.DesktopDisplay {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.cur == nil {
		return nil
	}
	return e.cur.displays
}
