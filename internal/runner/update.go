package runner

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/internal/transport"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// UpdateOptions włącza aktualizacje agenta. Brak (nil) oznacza agenta, który ignoruje oferty wydań.
type UpdateOptions struct {
	Paths update.Paths
	// Signers to zaufane klucze podpisu wydań (releasesig.TrustedSigners).
	Signers []ssh.PublicKey
	// HTTP pobiera artefakty; domyślnie klient z TLS 1.3 bez przekierowań.
	HTTP *http.Client
	// Verify sprawdza podpis Authenticode pobranego pliku; domyślnie update.CheckSignature.
	Verify func(path, subject string) error
	// RequestEvery to odstęp zapytań o ofertę wydania (domyślnie godzina).
	RequestEvery time.Duration
}

func (u *UpdateOptions) requestEvery() time.Duration {
	if u.RequestEvery > 0 {
		return u.RequestEvery
	}
	return time.Hour
}

// markStarted zapisuje start procesu i fazę „started” zdrowia: watchdog widzi, że nowa wersja wstała.
func (r *Runner) markStarted() {
	u := r.o.Update
	if u == nil {
		return
	}
	// Start po zamierzonym restarcie (polecenie agent.restart) nie liczy się do pętli awarii.
	if !u.Paths.ConsumeIntentionalRestart(time.Now()) {
		if err := u.Paths.RecordStart(time.Now()); err != nil {
			r.log.Warn("zapis startu agenta nieudany", "err", err)
		}
	}
	r.writeHealth(update.PhaseStarted)
}

func (r *Runner) writeHealth(phase string) {
	u := r.o.Update
	if u == nil {
		return
	}
	if err := u.Paths.WriteHealth(update.Health{Version: r.o.Versions.Agent, Phase: phase, PID: os.Getpid(), At: time.Now()}); err != nil {
		r.log.Warn("zapis zdrowia agenta nieudany", "err", err)
	}
}

// onConnected woła się po handshake i pierwszym heartbeacie: potwierdza zdrowie watchdogowi i zgłasza serwerowi
// wynik ostatniej podmiany, jeśli już jest.
func (r *Runner) onConnected(ctx context.Context) {
	if r.o.Update == nil {
		return
	}
	r.writeHealth(update.PhaseConnected)
	r.reportUpdateResult(ctx)
}

// reportUpdateResult zgłasza serwerowi wynik podmiany zapisany przez watchdoga i usuwa go po wysłaniu. Wynik
// powstaje dopiero po tym, jak watchdog zobaczy zdrowie nowej wersji, czyli już po jej pierwszym połączeniu,
// więc agent sprawdza plik także okresowo, a nie tylko przy połączeniu.
func (r *Runner) reportUpdateResult(ctx context.Context) {
	u := r.o.Update
	if u == nil {
		return
	}
	res, err := u.Paths.ReadResult()
	if err != nil {
		return
	}
	if err := r.sendTyped(ctx, wire.TypeUpdateStatus, wire.UpdateStatus{
		ReleaseID: res.ReleaseID, State: res.State, FromVersion: res.FromVersion, ToVersion: res.Version, Error: res.Error,
	}); err != nil {
		return // spróbujemy przy następnej okazji
	}
	_ = u.Paths.RemoveResult()
	r.log.Info("zgłoszono wynik aktualizacji", "state", res.State, "version", res.Version)
}

// requestRelease prosi serwer o ofertę wydania dla pierścienia tego urządzenia.
func (r *Runner) requestRelease(ctx context.Context) error {
	if r.o.Update == nil {
		return nil
	}
	return r.sendTyped(ctx, wire.TypeReleaseRequest, wire.ReleaseRequest{Component: "agent"})
}

// handleOffer przetwarza ofertę wydania: weryfikuje podpis i zgodność, pobiera plik, sprawdza go i przekazuje
// watchdogowi. Samą podmianę i rollback robi watchdog, bo działający agent nie może zastąpić własnego pliku.
func (r *Runner) handleOffer(ctx context.Context, offer wire.ReleaseAvailable) {
	switch offer.Component {
	case releasesig.ComponentRemoteModule:
		// Klient RustDesk instaluje aktywny menedżer pulpitu. Przy własnym silniku menedżer opakowuje pomocnika, a plik
		// RustDeska nie może trafić na jego miejsce, więc taka oferta jest odrzucana (serwer i tak jej nie wysyła).
		if r.Config().RemoteEngine == config.RemoteEngineWebRTC {
			r.log.Debug("oferta klienta RustDesk przy włączonym własnym silniku, pomijam", "version", offer.Version)
			return
		}
		if r.o.Remote == nil {
			return
		}
		r.installComponentOffer(ctx, offer, releasesig.ComponentRemoteModule, r.o.Remote, "remote", "moduł pulpitu", true)
		return
	case releasesig.ComponentDesktopHelper:
		if r.o.Helper == nil {
			return
		}
		// Pomocnik własnego silnika: plik ląduje obok agenta niezależnie od włączonego silnika; Prepare (zamknięcie dostępu)
		// dotyczy tylko aktywnego menedżera i tylko wtedy, gdy to on używa pomocnika.
		r.installComponentOffer(ctx, offer, releasesig.ComponentDesktopHelper, r.o.Helper, "helper", "pomocnik pulpitu", r.Config().RemoteEngine == config.RemoteEngineWebRTC)
		return
	}
	u := r.o.Update
	if u == nil {
		return
	}
	if !r.updMu.TryLock() {
		return // aktualizacja już trwa
	}
	defer r.updMu.Unlock()

	if u.Paths.IsBad(offer.ReleaseID) {
		r.log.Debug("wydanie odrzucone wcześniej na tym komputerze, pomijam", "release_id", offer.ReleaseID)
		return
	}
	if _, err := u.Paths.ReadRequest(); err == nil {
		return // poprzednia prośba czeka na watchdoga
	}

	current := r.o.Versions.Agent
	status := func(state, msg string) {
		if err := r.sendTyped(ctx, wire.TypeUpdateStatus, wire.UpdateStatus{ReleaseID: offer.ReleaseID, State: state, FromVersion: current, ToVersion: offer.Version, Error: msg}); err != nil {
			r.log.Debug("status aktualizacji niewysłany", "state", state, "err", err)
		}
	}
	fail := func(stage string, err error) {
		r.log.Error("aktualizacja odrzucona", "stage", stage, "version", offer.Version, "err", err)
		status(wire.UpdateFailed, fmt.Sprintf("%s: %v", stage, err))
	}

	planner := update.Planner{Signers: u.Signers, CurrentVersion: current, ServerURL: r.Config().ServerURL, Floor: u.Paths.Floor(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	m, err := planner.Plan(offer)
	if errors.Is(err, update.ErrUpToDate) {
		return
	}
	if err != nil {
		fail("weryfikacja oferty", err)
		return
	}

	// Próg z podpisanego manifestu zapamiętujemy od razu, także gdy sama aktualizacja się nie powiedzie.
	if err := u.Paths.RaiseFloor(m.MinVersion); err != nil {
		r.log.Warn("zapis progu bezpieczeństwa nieudany", "err", err)
	}
	r.log.Info("pobieram aktualizację", "from", current, "to", m.Version)
	status(wire.UpdateDownloading, "")
	client := u.HTTP
	if client == nil {
		client = transport.NewHTTPClient(0)
	}
	dest := filepath.Join(u.Paths.Staging(), fmt.Sprintf("agent-%s.exe", m.Version))
	dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	err = update.Download(dctx, client, m, dest)
	cancel()
	if err != nil {
		fail("pobieranie", err)
		return
	}

	verify := u.Verify
	if verify == nil {
		verify = update.CheckSignature
	}
	if err := verify(dest, m.AuthenticodeSubject); err != nil {
		_ = os.Remove(dest)
		fail("podpis pliku", err)
		return
	}
	status(wire.UpdateVerified, "")

	if err := u.Paths.WriteRequest(update.Request{
		ReleaseID: offer.ReleaseID, Component: m.Component, Version: m.Version, FromVersion: current, Path: dest,
		SHA256: m.Artifact.SHA256, Size: m.Artifact.Size, AuthenticodeSubject: m.AuthenticodeSubject,
		Manifest: offer.Manifest, Signature: offer.Signature, RequestedAt: time.Now().UTC(),
	}); err != nil {
		_ = os.Remove(dest)
		fail("przekazanie watchdogowi", err)
		return
	}
	status(wire.UpdateApplying, "")
	r.log.Info("aktualizacja przekazana watchdogowi", "to", m.Version)
}

// ComponentInstaller instaluje komponent pulpitu z pobranego, zweryfikowanego pliku (remote.Manager dla klienta
// RustDesk, remote.Engine dla pomocnika własnego silnika).
type ComponentInstaller interface {
	Version(ctx context.Context) string
	InstallVersion(ctx context.Context, path, version string) error
}

// installComponentOffer przetwarza ofertę komponentu pulpitu (remote_module albo desktop_helper). Weryfikacja jest ta sama
// co przy aktualizacji agenta (podpis sshsig manifestu kluczami z pliku, suma SHA-256, Authenticode ze zgodnym podmiotem),
// a zamiast podmiany własnego pliku agent instaluje komponent (cichy instalator producenta albo kopia pomocnika obok agenta).
// Próg bezpieczeństwa agenta nie dotyczy komponentów; cofanie wersji jest zabronione per komponent. Gdy prepare jest
// prawdą, po instalacji aktywny menedżer zamyka dostęp (Prepare), bo to on używa zainstalowanego pliku.
func (r *Runner) installComponentOffer(ctx context.Context, offer wire.ReleaseAvailable, component string, target ComponentInstaller, stagingPrefix, label string, prepare bool) {
	u := r.o.Update
	if u == nil {
		return
	}
	if !r.modMu.TryLock() {
		return // instalacja już trwa
	}
	defer r.modMu.Unlock()
	if u.Paths.IsBad(offer.ReleaseID) {
		r.log.Debug("wydanie modułu pulpitu odrzucone wcześniej na tym komputerze, pomijam", "release_id", offer.ReleaseID)
		return
	}

	current := target.Version(ctx)
	status := func(state, msg string) {
		if err := r.sendTyped(ctx, wire.TypeUpdateStatus, wire.UpdateStatus{ReleaseID: offer.ReleaseID, State: state, FromVersion: current, ToVersion: offer.Version, Error: msg}); err != nil {
			r.log.Debug("status instalacji modułu pulpitu niewysłany", "state", state, "err", err)
		}
	}
	fail := func(stage string, err error) {
		r.log.Error("instalacja komponentu pulpitu odrzucona", "component", label, "stage", stage, "version", offer.Version, "err", err)
		status(wire.UpdateFailed, fmt.Sprintf("%s: %v", stage, err))
	}

	planner := update.Planner{Component: component, Signers: u.Signers, CurrentVersion: current, ServerURL: r.Config().ServerURL, OS: runtime.GOOS, Arch: runtime.GOARCH}
	m, err := planner.Plan(offer)
	if errors.Is(err, update.ErrUpToDate) {
		return
	}
	if err != nil {
		fail("weryfikacja oferty", err)
		return
	}

	r.log.Info("pobieram komponent pulpitu", "component", label, "from", current, "to", m.Version)
	status(wire.UpdateDownloading, "")
	client := u.HTTP
	if client == nil {
		client = transport.NewHTTPClient(0)
	}
	dest := filepath.Join(u.Paths.Staging(), fmt.Sprintf("%s-%s.exe", stagingPrefix, m.Version))
	dctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	err = update.Download(dctx, client, m, dest)
	cancel()
	if err != nil {
		fail("pobieranie", err)
		return
	}
	defer os.Remove(dest)

	verify := u.Verify
	if verify == nil {
		verify = update.CheckSignature
	}
	if err := verify(dest, m.AuthenticodeSubject); err != nil {
		fail("podpis pliku", err)
		return
	}
	status(wire.UpdateVerified, "")

	status(wire.UpdateApplying, "")
	if err := target.InstallVersion(ctx, dest, m.Version); err != nil {
		// Nieudana instalacja nie jest ponawiana w pętli: wydanie trafia na lokalną listę odrzuconych.
		_ = u.Paths.MarkBad(offer.ReleaseID)
		fail("instalacja", err)
		return
	}
	if prepare && r.o.Remote != nil {
		if err := r.o.Remote.Prepare(ctx); err != nil {
			r.log.Warn("konfiguracja komponentu pulpitu po instalacji nieudana", "component", label, "err", err)
		}
	}
	status(wire.UpdateSuccess, "")
	r.log.Info("komponent pulpitu zainstalowany", "component", label, "version", m.Version)
}
