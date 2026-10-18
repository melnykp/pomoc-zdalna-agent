package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Granice czasu życia hasła jednorazowego (od remote.open do połączenia).
const (
	DefaultTTL = 120 * time.Second
	MinTTL     = 30 * time.Second
	MaxTTL     = 10 * time.Minute
)

// StateFunc dostaje zmiany stanu sesji do odesłania serwerowi (remote.state). Statystyki (nil dla RustDesk) wypełnia
// własny silnik przy końcu sesji.
type StateFunc func(sessionID, state string, stats *wire.RemoteStats)

// Manager prowadzi sesje pulpitu: jedna naraz. Nie przechowuje hasła nigdzie poza pamięcią procesu.
type Manager struct {
	mod  Module
	now  func() time.Time
	poll time.Duration
	log  *slog.Logger
	emit StateFunc

	mu  sync.Mutex
	cur *Session

	verMu sync.Mutex
	ver   string
	verAt time.Time
}

// Options konfiguruje menedżera. Zero w polach czasu oznacza wartości domyślne.
type Options struct {
	Module Module
	Log    *slog.Logger
	Emit   StateFunc
	// Now i Poll służą testom.
	Now  func() time.Time
	Poll time.Duration
}

// NewManager tworzy menedżera sesji.
func NewManager(o Options) *Manager {
	m := &Manager{mod: o.Module, now: o.Now, poll: o.Poll, log: o.Log, emit: o.Emit}
	if m.now == nil {
		m.now = time.Now
	}
	if m.poll <= 0 {
		m.poll = 2 * time.Second
	}
	if m.log == nil {
		m.log = slog.Default()
	}
	if m.emit == nil {
		m.emit = func(string, string, *wire.RemoteStats) {}
	}
	return m
}

// Signal przekazuje sygnalizację WebRTC widza do modułu bieżącej sesji. Oferta spoza trwającej sesji jest odrzucana
// (ErrNoSession): to serwer trzyma, kto i kiedy może się połączyć, a agent tylko sprawdza zgodność z remote.open.
func (m *Manager) Signal(ctx context.Context, sessionID string, sig wire.RemoteSignal) (*wire.RemoteSignal, error) {
	sg, ok := m.mod.(Signaler)
	if !ok {
		return nil, ErrNoSignaling
	}
	m.mu.Lock()
	if m.cur == nil || m.cur.ID != sessionID {
		m.mu.Unlock()
		return nil, ErrNoSession
	}
	if m.cur.ConnectedAt.IsZero() && !m.now().Before(m.cur.ExpiresAt) {
		m.mu.Unlock()
		return nil, ErrNoSession // czas na połączenie minął; pętla zaraz zamknie sesję
	}
	sessCtx := m.cur.ctx
	m.mu.Unlock()
	// Bez blokady: oferta czeka na pomocnika do kilkunastu sekund, a pętla obserwacji musi tykać. Kontekst gaśnie razem
	// z sesją (remote.close, wygaśnięcie), żeby oferta w toku nie zostawiła pomocnika bez ewidencji.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(sessCtx, cancel)
	defer stop()
	return sg.Signal(ctx, sessionID, sig)
}

// Install instaluje klienta pulpitu z pliku instalacyjnego (wcześniej zweryfikowanego przez wywołującego) i unieważnia
// zapamiętaną wersję. Błąd ErrNoInstaller, gdy moduł nie umie instalować.
func (m *Manager) Install(ctx context.Context, installerPath string) error {
	return m.InstallVersion(ctx, installerPath, "")
}

// InstallVersion to Install ze znaną wersją komponentu (dla modułów, które ją zapisują obok pliku).
func (m *Manager) InstallVersion(ctx context.Context, installerPath, version string) error {
	inst, ok := m.mod.(Installer)
	if !ok {
		return ErrNoInstaller
	}
	m.mu.Lock()
	busy := m.cur != nil
	m.mu.Unlock()
	if busy {
		return ErrBusy // nie podmieniamy klienta w trakcie sesji
	}
	var err error
	if vi, ok := m.mod.(VersionedInstaller); ok && version != "" {
		err = vi.InstallVersion(ctx, installerPath, version)
	} else {
		err = inst.Install(ctx, installerPath)
	}
	m.verMu.Lock()
	m.verAt = time.Time{}
	m.verMu.Unlock()
	return err
}

// Version zwraca wersję zainstalowanego klienta albo pusty tekst, gdy klienta nie ma lub nie podaje wersji. Wynik jest
// pamiętany przez 5 minut, bo wołają go raporty stanu co 30 sekund, a odczyt uruchamia proces klienta.
func (m *Manager) Version(ctx context.Context) string {
	v, ok := m.mod.(Versioner)
	if !ok || !m.mod.Installed() {
		return ""
	}
	m.verMu.Lock()
	defer m.verMu.Unlock()
	if !m.verAt.IsZero() && m.now().Sub(m.verAt) < 5*time.Minute {
		return m.ver
	}
	m.ver = v.Version(ctx)
	m.verAt = m.now()
	return m.ver
}

// Prepare ustawia bezpieczny stan wyjściowy: opcje klienta i hasło zamykające. Wołane przy starcie agenta, więc po
// awarii w trakcie sesji komputer nie zostaje z ważnym hasłem. Gdy klienta nie ma, nic nie robi.
func (m *Manager) Prepare(ctx context.Context) error {
	if !m.mod.Installed() {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		// Trwa sesja: hasło zamykające nadpisałoby hasło jednorazowe i inżynier by się nie połączył.
		return ErrBusy
	}
	if err := m.mod.EnsureConfig(ctx); err != nil {
		return fmt.Errorf("konfiguracja klienta pulpitu: %w", err)
	}
	return m.lock(ctx)
}

// Open rozpoczyna sesję: ustawia hasło jednorazowe i zwraca dane do połączenia. Czas życia jest przycinany do
// przedziału MinTTL..MaxTTL (zero oznacza DefaultTTL).
func (m *Manager) Open(ctx context.Context, sessionID string, ttl time.Duration) (Session, error) {
	if !m.mod.Installed() {
		return Session{}, ErrNotInstalled
	}
	switch {
	case ttl <= 0:
		ttl = DefaultTTL
	case ttl < MinTTL:
		ttl = MinTTL
	case ttl > MaxTTL:
		ttl = MaxTTL
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		if m.cur.ConnectedAt.IsZero() && !m.now().Before(m.cur.ExpiresAt) {
			// Poprzednia sesja wygasła, ale pętla jeszcze jej nie zamknęła.
			m.closeLocked(ctx, StateExpired)
		} else {
			return Session{}, ErrBusy
		}
	}

	if err := m.mod.EnsureConfig(ctx); err != nil {
		return Session{}, fmt.Errorf("konfiguracja klienta pulpitu: %w", err)
	}
	id, err := m.mod.ID(ctx)
	if err != nil {
		return Session{}, fmt.Errorf("odczyt identyfikatora: %w", err)
	}
	otp, err := GenerateOTP(OTPLength)
	if err != nil {
		return Session{}, err
	}
	if err := m.mod.SetPassword(ctx, otp); err != nil {
		return Session{}, fmt.Errorf("ustawienie hasła sesji: %w", err)
	}
	engine := wire.RemoteEngineRustDesk
	if n, ok := m.mod.(EngineNamer); ok {
		engine = n.Engine()
	}
	sctx, scancel := context.WithCancel(context.Background())
	m.cur = &Session{ID: sessionID, RemoteID: id, OTP: otp, ExpiresAt: m.now().Add(ttl), Engine: engine, ctx: sctx, cancel: scancel}
	return *m.cur, nil
}

// Close zamyka dostęp i kończy sesję (polecenie remote.close). Pusty identyfikator oznacza bieżącą sesję. Zamknięcie
// nieznanej sesji nie jest błędem krytycznym: dostęp i tak jest zamykany.
func (m *Manager) Close(ctx context.Context, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return m.lock(ctx)
	}
	if sessionID != "" && m.cur.ID != sessionID {
		return ErrNoSession
	}
	m.closeLocked(ctx, StateClosed)
	return nil
}

// Active zwraca bieżącą sesję (bez hasła), jeśli trwa.
func (m *Manager) Active() (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return Session{}, false
	}
	s := *m.cur
	s.OTP = ""
	return s, true
}

// Run obserwuje bieżącą sesję: zgłasza połączenie i rozłączenie, zamyka dostęp po wygaśnięciu hasła. Działa do końca ctx.
func (m *Manager) Run(ctx context.Context) {
	t := time.NewTicker(m.poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Tick(ctx)
		}
	}
}

// Tick wykonuje jeden obrót pętli obserwacji. Wydzielony, żeby testy nie czekały na zegar.
func (m *Manager) Tick(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur == nil {
		return
	}
	connected, err := m.mod.Connected(ctx)
	if err != nil {
		m.log.Debug("odczyt stanu połączenia pulpitu nieudany", "err", err)
	}
	switch {
	case err == nil && connected && m.cur.ConnectedAt.IsZero():
		m.cur.ConnectedAt = m.now()
		m.emit(m.cur.ID, StateConnected, nil)
	case err == nil && !connected && !m.cur.ConnectedAt.IsZero():
		m.closeLocked(ctx, StateDisconnected)
	case m.cur.ConnectedAt.IsZero() && !m.now().Before(m.cur.ExpiresAt):
		m.closeLocked(ctx, StateExpired)
	}
}

// closeLocked zamyka dostęp, zgłasza stan i kończy sesję. Wymaga trzymanego m.mu.
func (m *Manager) closeLocked(ctx context.Context, state string) {
	id := m.cur.ID
	if m.cur.cancel != nil {
		m.cur.cancel() // oferta w toku dla tej sesji ma się przerwać i zabić pomocnika
	}
	m.cur = nil
	var stats *wire.RemoteStats
	if e, ok := m.mod.(SessionEnder); ok {
		stats = e.EndSession(ctx)
	}
	if err := m.lock(ctx); err != nil {
		// Nie udało się zamknąć dostępu: stan sesji i tak zgłaszamy, ale głośno ostrzegamy. Hasło jednorazowe jest
		// ważne dalej, więc próbę powtórzy kolejne Prepare (start agenta) albo następna sesja.
		m.log.Error("nie udało się zamknąć dostępu pulpitu po sesji", "err", err, "session_id", id)
	}
	m.emit(id, state, stats)
}

// lock ustawia losowe hasło, którego nikt nie zna.
func (m *Manager) lock(ctx context.Context) error {
	if !m.mod.Installed() {
		return nil
	}
	pw, err := LockPassword()
	if err != nil {
		return err
	}
	if err := m.mod.SetPassword(ctx, pw); err != nil {
		return errors.Join(errors.New("hasło zamykające"), err)
	}
	return nil
}
