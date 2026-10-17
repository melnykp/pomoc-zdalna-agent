package runner_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// installableDesktop to klient pulpitu, który umie się zainstalować i podać wersję (jak RustDesk).
type installableDesktop struct {
	*fakeDesktop
	vmu           sync.Mutex
	version       string
	installedBody []byte
	installErr    error
	installs      int
}

func (f *installableDesktop) Version(context.Context) string {
	f.vmu.Lock()
	defer f.vmu.Unlock()
	return f.version
}

func (f *installableDesktop) Install(_ context.Context, path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	f.vmu.Lock()
	defer f.vmu.Unlock()
	f.installs++
	f.installedBody = body
	if f.installErr != nil {
		return f.installErr
	}
	f.fakeDesktop.installed = true
	f.version = "1.5.0"
	return nil
}

func (f *installableDesktop) snapshot() (int, []byte, string) {
	f.vmu.Lock()
	defer f.vmu.Unlock()
	return f.installs, f.installedBody, f.version
}

type moduleEnv struct {
	*updEnv
	body      []byte
	downloads atomic.Int32
	artifact  func(w http.ResponseWriter)
}

func setupModule(t *testing.T) (*moduleEnv, *installableDesktop) {
	t.Helper()
	u := setupUpdate(t)
	m := &moduleEnv{updEnv: u, body: []byte(strings.Repeat("MZ-rustdesk-1.5.0-", 400))}
	m.artifact = func(w http.ResponseWriter) { _, _ = w.Write(m.body) }
	u.srv.Handle("/v1/releases/artifacts/remote-1.5.0.exe", func(w http.ResponseWriter, r *http.Request) {
		m.downloads.Add(1)
		m.artifact(w)
	})
	mod := &installableDesktop{fakeDesktop: &fakeDesktop{installed: false}}
	return m, mod
}

// moduleOffer buduje podpisaną ofertę komponentu remote_module z artefaktem hostowanym przez atrapę.
func (m *moduleEnv) moduleOffer(t *testing.T, signer ssh.Signer, id string, mutate func(*releasesig.Manifest)) wire.Envelope {
	t.Helper()
	sum := sha256.Sum256(m.body)
	man := releasesig.Manifest{
		Schema: releasesig.SchemaVersion, Component: releasesig.ComponentRemoteModule, Version: "1.5.0", OS: runtime.GOOS, Arch: runtime.GOARCH,
		Artifact:            releasesig.Artifact{URL: m.srv.URL() + "/v1/releases/artifacts/remote-1.5.0.exe", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(m.body))},
		AuthenticodeSubject: "CN=PURSLANE, O=PURSLANE, C=SG", ReleasedAt: "2026-10-17T10:00:00Z",
	}
	if mutate != nil {
		mutate(&man)
	}
	raw, _ := json.MarshalIndent(man, "", "  ")
	raw = append(raw, '\n')
	sig, err := releasesig.SignSSHSig(raw, signer)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.NewEnvelope(wire.TypeReleaseAvailable, wire.ReleaseAvailable{ReleaseID: id, Component: "remote_module", Ring: "canary", Version: man.Version, Manifest: string(raw), Signature: string(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func TestModuleOfferIsVerifiedDownloadedAndInstalled(t *testing.T) {
	m, mod := setupModule(t)
	mgr := startWithRemote(t, m.env, mod)
	_ = mgr

	if err := m.srv.Send(deviceID, m.moduleOffer(t, m.signer, "rel-rd-150", nil)); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, m.srv, typ) }, 4)
	want := []string{wire.UpdateDownloading, wire.UpdateVerified, wire.UpdateApplying, wire.UpdateSuccess}
	for i, s := range got {
		if s.State != want[i] || s.ReleaseID != "rel-rd-150" || s.ToVersion != "1.5.0" {
			t.Fatalf("etap %d: %+v, oczekiwano %s", i, s, want[i])
		}
	}
	installs, body, version := mod.snapshot()
	if installs != 1 || string(body) != string(m.body) || version != "1.5.0" {
		t.Fatalf("instalacja: razy=%d zgodny plik=%v wersja=%q", installs, string(body) == string(m.body), version)
	}
	// Po instalacji agent konfiguruje klienta i zamyka dostęp (hasło zamykające).
	waitFor(t, "hasło zamykające po instalacji", func() bool { return len(mod.last()) == 48 })
}

func TestModuleOfferFromUntrustedKeyIsNeverInstalled(t *testing.T) {
	m, mod := setupModule(t)
	startWithRemote(t, m.env, mod)

	if err := m.srv.Send(deviceID, m.moduleOffer(t, newSigner(t), "rel-rd-bad", nil)); err != nil {
		t.Fatal(err)
	}
	var s wire.UpdateStatus
	if err := next(t, m.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateFailed || !strings.Contains(s.Error, "weryfikacja oferty") {
		t.Fatalf("oferta z obcym kluczem powinna zostać odrzucona: %+v", s)
	}
	if installs, _, _ := mod.snapshot(); installs != 0 || m.downloads.Load() != 0 {
		t.Fatalf("nic nie może zostać pobrane ani zainstalowane: instalacje=%d pobrania=%d", installs, m.downloads.Load())
	}
}

func TestModuleArtifactTamperedOnServerIsNotInstalled(t *testing.T) {
	m, mod := setupModule(t)
	startWithRemote(t, m.env, mod)
	m.artifact = func(w http.ResponseWriter) { _, _ = w.Write([]byte(strings.Repeat("ZMIENIONY", 500))) }

	if err := m.srv.Send(deviceID, m.moduleOffer(t, m.signer, "rel-rd-tampered", nil)); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, m.srv, typ) }, 2)
	if got[1].State != wire.UpdateFailed || !strings.Contains(got[1].Error, "pobieranie") {
		t.Fatalf("zmieniony plik powinien zostać odrzucony przy pobieraniu: %+v", got)
	}
	if installs, _, _ := mod.snapshot(); installs != 0 {
		t.Fatal("zmieniony plik nie może zostać zainstalowany")
	}
}

func TestModuleOfferForInstalledVersionDoesNothing(t *testing.T) {
	m, mod := setupModule(t)
	mod.fakeDesktop.installed = true
	mod.version = "1.5.0"
	startWithRemote(t, m.env, mod)

	if err := m.srv.Send(deviceID, m.moduleOffer(t, m.signer, "rel-rd-same", nil)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if installs, _, _ := mod.snapshot(); installs != 0 || m.downloads.Load() != 0 {
		t.Fatalf("zainstalowana wersja nie wymaga pobierania: instalacje=%d pobrania=%d", installs, m.downloads.Load())
	}
}

func TestModuleOfferForOlderVersionThanInstalledIsRefused(t *testing.T) {
	m, mod := setupModule(t)
	mod.fakeDesktop.installed = true
	mod.version = "1.6.0"
	startWithRemote(t, m.env, mod)

	if err := m.srv.Send(deviceID, m.moduleOffer(t, m.signer, "rel-rd-old", nil)); err != nil {
		t.Fatal(err)
	}
	var s wire.UpdateStatus
	if err := next(t, m.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateFailed || !strings.Contains(s.Error, "cofanie zabronione") {
		t.Fatalf("starsza wersja modułu powinna zostać odrzucona: %+v", s)
	}
	if installs, _, _ := mod.snapshot(); installs != 0 {
		t.Fatal("starszy moduł nie może zostać zainstalowany")
	}
}

func TestFailedModuleInstallIsNotRetriedInALoop(t *testing.T) {
	m, mod := setupModule(t)
	mod.installErr = context.DeadlineExceeded
	startWithRemote(t, m.env, mod)

	offer := m.moduleOffer(t, m.signer, "rel-rd-fail", nil)
	if err := m.srv.Send(deviceID, offer); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, m.srv, typ) }, 4)
	if got[3].State != wire.UpdateFailed || !strings.Contains(got[3].Error, "instalacja") {
		t.Fatalf("nieudana instalacja powinna zostać zgłoszona: %+v", got)
	}

	// Ta sama oferta po raz drugi jest ignorowana (wydanie na lokalnej liście odrzuconych).
	downloads := m.downloads.Load()
	if err := m.srv.Send(deviceID, offer); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if m.downloads.Load() != downloads {
		t.Fatal("odrzucone wydanie modułu nie może być pobierane ponownie")
	}
}
