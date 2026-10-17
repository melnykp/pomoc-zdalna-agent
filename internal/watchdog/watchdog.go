// Package watchdog to logika nadzorcy agenta (docs/ARCHITECTURE.md): pilnuje, żeby agent działał,
// wykonuje podmianę jego pliku po własnej weryfikacji, czeka na jego zdrowie i wraca do poprzedniej wersji, gdy
// nowa nie wstaje albo wpada w pętlę awarii. Nie łączy się z serwerem poza opcjonalnym sprawdzeniem
// osiągalności, a o wyniku informuje agent po jego następnym starcie (pliki stanu w katalogu danych).
//
// Logika jest niezależna od platformy: sterowanie usługą to interfejs Controller. W Windows jest nim menedżer
// usług, w rozwoju i w testach proces potomny.
package watchdog

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
)

// Controller steruje procesem agenta.
type Controller interface {
	// Stop zatrzymuje agenta i czeka, aż jego plik przestanie być zajęty.
	Stop(ctx context.Context) error
	// Start uruchamia agenta i nie czeka na jego zdrowie. Start działającego agenta nie jest błędem.
	Start(ctx context.Context) error
	// Running mówi, czy agent działa.
	Running() bool
}

// Verifier sprawdza podpis Authenticode pliku (update.CheckSignature w produkcji).
type Verifier func(path, wantSubject string) error

// Options konfiguruje watchdoga. Zerowe czasy dostają wartości domyślne.
type Options struct {
	Paths      update.Paths
	AgentPath  string
	Controller Controller
	Verify     Verifier
	Log        *slog.Logger

	// ServerReachable mówi, czy komputer w ogóle dosięga serwera. Gdy nowa wersja nie zdążyła się połączyć, a serwer
	// jest nieosiągalny dla całego komputera, nie wolno jej obwiniać o brak połączenia.
	ServerReachable func(ctx context.Context) bool

	HealthTimeout time.Duration // 120 s
	PollInterval  time.Duration // 2 s
	CrashWindow   time.Duration // 10 min
	CrashLimit    int           // 3 restarty w oknie
	// CrashRollbackWithin to jak długo po udanej podmianie pętla awarii powoduje rollback (24 h).
	CrashRollbackWithin time.Duration
	Now                 func() time.Time
}

// Watchdog nadzoruje agenta.
type Watchdog struct {
	o   Options
	log *slog.Logger
}

// New tworzy watchdoga z uzupełnionymi wartościami domyślnymi.
func New(o Options) *Watchdog {
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.HealthTimeout == 0 {
		o.HealthTimeout = 120 * time.Second
	}
	if o.PollInterval == 0 {
		o.PollInterval = 2 * time.Second
	}
	if o.CrashWindow == 0 {
		o.CrashWindow = 10 * time.Minute
	}
	if o.CrashLimit == 0 {
		o.CrashLimit = 3
	}
	if o.CrashRollbackWithin == 0 {
		o.CrashRollbackWithin = 24 * time.Hour
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.ServerReachable == nil {
		o.ServerReachable = func(context.Context) bool { return false }
	}
	return &Watchdog{o: o, log: o.Log}
}

func (w *Watchdog) prevPath() string { return w.o.AgentPath + ".prev" }
func (w *Watchdog) badPath() string  { return w.o.AgentPath + ".bad" }

// Run działa do anulowania ctx: wykonuje prośby o podmianę, pilnuje pętli awarii i dbą o to, żeby agent działał.
func (w *Watchdog) Run(ctx context.Context) error {
	w.log.Info("watchdog start", "agent", w.o.AgentPath)
	t := time.NewTicker(w.o.PollInterval)
	defer t.Stop()
	for {
		w.Tick(ctx)
		select {
		case <-ctx.Done():
			w.log.Info("watchdog stop")
			return nil
		case <-t.C:
		}
	}
}

// Tick wykonuje jeden obrót pętli nadzoru. Wydzielony, żeby testy nie czekały na zegar.
func (w *Watchdog) Tick(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	req, err := w.o.Paths.ReadRequest()
	switch {
	case err == nil:
		w.Apply(ctx, req)
		return
	case !errors.Is(err, update.ErrNone):
		w.log.Error("nieczytelna prośba o podmianę, usuwam", "err", err)
		_ = w.o.Paths.RemoveRequest()
	}

	if w.crashLoopRollback(ctx) {
		return
	}
	if !w.o.Controller.Running() {
		w.log.Warn("agent nie działa, uruchamiam")
		if err := w.o.Controller.Start(ctx); err != nil {
			w.log.Error("start agenta nieudany", "err", err)
		}
	}
}

// Apply wykonuje prośbę o podmianę pliku agenta i zapisuje wynik dla agenta. Zawsze usuwa prośbę.
func (w *Watchdog) Apply(ctx context.Context, req update.Request) update.Result {
	w.log.Info("podmiana agenta", "req", req.String())
	defer func() { _ = w.o.Paths.RemoveRequest() }()

	res := update.Result{ReleaseID: req.ReleaseID, Version: req.Version, FromVersion: req.FromVersion, At: w.o.Now()}
	finish := func(state, msg string) update.Result {
		res.State, res.Error, res.At = state, msg, w.o.Now()
		if err := w.o.Paths.WriteResult(res); err != nil {
			w.log.Error("zapis wyniku podmiany nieudany", "err", err)
		}
		return res
	}

	// 1. Własna weryfikacja pliku: watchdog nie ufa agentowi.
	if err := w.validate(req); err != nil {
		w.log.Error("odrzucono plik do podmiany", "err", err)
		w.removeStaged(req.Path)
		return finish(update.StateFailed, err.Error())
	}

	// 2. Podmiana: stop, poprzedni plik do .prev, nowy na jego miejsce.
	if err := w.o.Controller.Stop(ctx); err != nil {
		_ = w.o.Controller.Start(ctx)
		return finish(update.StateFailed, fmt.Sprintf("zatrzymanie agenta: %v", err))
	}
	if err := w.swapIn(req.Path); err != nil {
		w.restorePrev()
		_ = w.o.Controller.Start(ctx)
		return finish(update.StateFailed, fmt.Sprintf("podmiana pliku: %v", err))
	}
	_ = w.o.Paths.RemoveHealth()
	_ = w.o.Paths.ClearStarts()
	started := w.o.Now()
	if err := w.o.Controller.Start(ctx); err != nil {
		w.log.Error("start nowej wersji nieudany", "err", err)
	}

	// 3. Zdrowie nowej wersji albo rollback.
	switch w.awaitHealth(ctx, req.Version, started) {
	case healthy:
		_ = os.Remove(req.Path)
		_ = w.o.Paths.WriteLastUpdate(update.LastUpdate{ReleaseID: req.ReleaseID, Version: req.Version, FromVersion: req.FromVersion, At: w.o.Now()})
		w.log.Info("podmiana udana", "version", req.Version)
		return finish(update.StateSuccess, "")
	case offline:
		// Proces wstał, ale komputer nie dosięga serwera, więc nic nie wskazuje na winę nowej wersji.
		_ = os.Remove(req.Path)
		_ = w.o.Paths.WriteLastUpdate(update.LastUpdate{ReleaseID: req.ReleaseID, Version: req.Version, FromVersion: req.FromVersion, At: w.o.Now()})
		w.log.Warn("nowa wersja działa, ale serwer jest nieosiągalny dla całego komputera: zostaje", "version", req.Version)
		return finish(update.StateSuccess, "")
	default:
		w.log.Error("nowa wersja nie potwierdziła zdrowia, wracam do poprzedniej", "version", req.Version)
		if err := w.rollback(ctx, req.FromVersion); err != nil {
			return finish(update.StateFailed, fmt.Sprintf("nowa wersja nie wstała, a rollback się nie udał: %v", err))
		}
		_ = w.o.Paths.MarkBad(req.ReleaseID)
		return finish(update.StateRolledBack, "nowa wersja nie połączyła się z serwerem w wyznaczonym czasie")
	}
}

type healthOutcome int

const (
	unhealthy healthOutcome = iota
	healthy
	offline
)

func (w *Watchdog) awaitHealth(ctx context.Context, version string, since time.Time) healthOutcome {
	deadline := w.o.Now().Add(w.o.HealthTimeout)
	started := false
	for {
		if h, err := w.o.Paths.ReadHealth(); err == nil && h.Version == version && !h.At.Before(since.Add(-time.Second)) {
			if h.Phase == update.PhaseConnected {
				return healthy
			}
			started = true
		}
		if w.o.Now().After(deadline) || ctx.Err() != nil {
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(w.o.PollInterval / 4):
		}
	}
	if started {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if !w.o.ServerReachable(rctx) {
			return offline
		}
	}
	return unhealthy
}

// validate sprawdza prośbę i plik: ścieżka tylko w staging, rozmiar i suma, podpis Authenticode.
func (w *Watchdog) validate(req update.Request) error {
	if req.Component != "agent" {
		return fmt.Errorf("nieobsługiwany komponent %q", req.Component)
	}
	if !w.inStaging(req.Path) {
		return fmt.Errorf("plik poza katalogiem staging: %q", req.Path)
	}
	if req.Version == "" || req.FromVersion == "" || req.ReleaseID == "" {
		return errors.New("prośba bez wersji lub identyfikatora wydania")
	}
	if err := update.VerifyFile(req.Path, artifactOf(req)); err != nil {
		return err
	}
	if w.o.Verify != nil {
		if err := w.o.Verify(req.Path, req.AuthenticodeSubject); err != nil {
			return err
		}
	}
	return nil
}

// swapIn przenosi bieżący plik agenta do .prev i wstawia nowy. Przy błędzie zostawia .prev do przywrócenia.
func (w *Watchdog) swapIn(staged string) error {
	_ = os.Remove(w.prevPath())
	if err := os.Rename(w.o.AgentPath, w.prevPath()); err != nil {
		return fmt.Errorf("przeniesienie poprzedniej wersji: %w", err)
	}
	if err := moveFile(staged, w.o.AgentPath); err != nil {
		return fmt.Errorf("wstawienie nowej wersji: %w", err)
	}
	// Plik ze staging ma tryb 0600, a zmiana nazwy go zachowuje: bez bitu wykonywania nowa wersja nie wystartuje (Linux).
	if err := os.Chmod(w.o.AgentPath, 0o755); err != nil {
		return fmt.Errorf("uprawnienia nowej wersji: %w", err)
	}
	return nil
}

// restorePrev przywraca poprzedni plik, jeśli podmiana nie dokończyła się.
func (w *Watchdog) restorePrev() {
	if _, err := os.Stat(w.prevPath()); err != nil {
		return
	}
	_ = os.Remove(w.o.AgentPath)
	if err := os.Rename(w.prevPath(), w.o.AgentPath); err != nil {
		w.log.Error("przywrócenie poprzedniej wersji nieudane", "err", err)
	}
}

// rollback zatrzymuje agenta, zamienia pliki z powrotem i startuje poprzednią wersję, sprawdzając jej zdrowie.
func (w *Watchdog) rollback(ctx context.Context, fromVersion string) error {
	if _, err := os.Stat(w.prevPath()); err != nil {
		return errors.New("brak poprzedniej wersji (.prev)")
	}
	if err := w.o.Controller.Stop(ctx); err != nil {
		return fmt.Errorf("zatrzymanie: %w", err)
	}
	_ = os.Remove(w.badPath())
	if err := os.Rename(w.o.AgentPath, w.badPath()); err != nil {
		return fmt.Errorf("odłożenie wadliwej wersji: %w", err)
	}
	if err := os.Rename(w.prevPath(), w.o.AgentPath); err != nil {
		return fmt.Errorf("przywrócenie poprzedniej wersji: %w", err)
	}
	_ = w.o.Paths.RemoveHealth()
	_ = w.o.Paths.ClearStarts()
	_ = w.o.Paths.RemoveLastUpdate()
	started := w.o.Now()
	if err := w.o.Controller.Start(ctx); err != nil {
		return fmt.Errorf("start poprzedniej wersji: %w", err)
	}
	if w.awaitHealth(ctx, fromVersion, started) == unhealthy {
		w.log.Error("poprzednia wersja też nie potwierdziła zdrowia po rollbacku", "version", fromVersion)
	}
	return nil
}

// crashLoopRollback wraca do poprzedniej wersji, gdy świeżo zaktualizowany agent restartuje się zbyt często.
// Zwraca true, gdy wykonano rollback.
func (w *Watchdog) crashLoopRollback(ctx context.Context) bool {
	last, err := w.o.Paths.ReadLastUpdate()
	if err != nil || w.o.Now().Sub(last.At) > w.o.CrashRollbackWithin {
		return false
	}
	if w.o.Paths.StartsSince(w.o.Now().Add(-w.o.CrashWindow)) < w.o.CrashLimit {
		return false
	}
	w.log.Error("pętla awarii po aktualizacji, wracam do poprzedniej wersji", "version", last.Version, "restarty", w.o.CrashLimit)
	if err := w.rollback(ctx, last.FromVersion); err != nil {
		w.log.Error("rollback po pętli awarii nieudany", "err", err)
		_ = w.o.Paths.RemoveLastUpdate()
		return true
	}
	_ = w.o.Paths.MarkBad(last.ReleaseID)
	_ = w.o.Paths.WriteResult(update.Result{
		ReleaseID: last.ReleaseID, Version: last.Version, FromVersion: last.FromVersion,
		State: update.StateRolledBack, Error: "agent wpadał w pętlę awarii po aktualizacji", At: w.o.Now(),
	})
	return true
}

// moveFile przenosi plik; gdy zmiana nazwy nie jest możliwa (inny wolumin), kopiuje i usuwa źródło.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Remove(src)
	return nil
}

// inStaging mówi, czy ścieżka wskazuje plik wewnątrz katalogu staging. Prośba pochodzi z pliku, więc ścieżce nie ufamy.
func (w *Watchdog) inStaging(path string) bool {
	rel, err := filepath.Rel(w.o.Paths.Staging(), path)
	if err != nil || filepath.IsAbs(rel) || rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// removeStaged kasuje plik tylko wtedy, gdy leży w staging. Odrzucona prośba nie może posłużyć do skasowania
// dowolnego pliku, w tym samego agenta.
func (w *Watchdog) removeStaged(path string) {
	if w.inStaging(path) {
		_ = os.Remove(path)
	}
}
