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
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/remote"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// fakeHelper udaje instalator pomocnika własnego silnika (komponent desktop_helper): liczy instalacje i pamięta wersję.
type fakeHelper struct {
	mu       sync.Mutex
	version  string
	installs int
	body     []byte
	// stan pomocnika zgłaszany jak przez remote.Engine (runner.HelperReporter); pusty poziom = brak raportu silnika
	level, token string
	fallback     bool
	session, uac string
}

func (h *fakeHelper) HelperStatus() remote.HelperStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return remote.HelperStatus{Level: h.level, Token: h.token, Fallback: h.fallback, SessionLevel: h.session, UAC: h.uac}
}

func (h *fakeHelper) Version(context.Context) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.version
}

func (h *fakeHelper) InstallVersion(_ context.Context, path, version string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.installs++
	h.body = body
	h.version = version
	return nil
}

func (h *fakeHelper) snapshot() (int, string, []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.installs, h.version, h.body
}

// helperOffer buduje podpisaną ofertę komponentu desktop_helper hostowaną przez atrapę serwera.
func helperOffer(t *testing.T, u *updEnv, signer ssh.Signer, id, version string, body []byte, component string) wire.Envelope {
	t.Helper()
	sum := sha256.Sum256(body)
	man := releasesig.Manifest{
		Schema: releasesig.SchemaVersion, Component: component, Version: version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Artifact:            releasesig.Artifact{URL: u.srv.URL() + "/v1/releases/artifacts/helper-" + version + ".exe", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body))},
		AuthenticodeSubject: "CN=Piotr Melnyk IT, O=Piotr Melnyk IT, C=PL", ReleasedAt: "2026-10-18T10:00:00Z",
	}
	raw, _ := json.MarshalIndent(man, "", "  ")
	raw = append(raw, '\n')
	sig, err := releasesig.SignSSHSig(raw, signer)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.NewEnvelope(wire.TypeReleaseAvailable, wire.ReleaseAvailable{ReleaseID: id, Component: component, Ring: "canary", Version: version, Manifest: string(raw), Signature: string(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func setupHelper(t *testing.T) (*updEnv, *fakeHelper, []byte) {
	t.Helper()
	u := setupUpdate(t)
	body := []byte(strings.Repeat("MZ-desktop-helper-0.4.0-", 300))
	u.srv.Handle("/v1/releases/artifacts/helper-0.4.0.exe", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) })
	h := &fakeHelper{}
	u.opts.Helper = h
	return u, h, body
}

// Pomocnik instaluje się także wtedy, gdy włączony jest RustDesk: przełączenie na własny silnik ma zastać plik na miejscu.
func TestHelperOfferInstallsRegardlessOfActiveEngine(t *testing.T) {
	u, h, body := setupHelper(t)
	mod := &fakeDesktop{installed: true}
	startWithRemote(t, u.env, mod)
	// Menedżer zamyka dostęp przy starcie (hasło zamykające); to jedyne hasło, jakie ma paść w tym teście.
	waitFor(t, "hasło zamykające przy starcie", func() bool { return len(mod.last()) == 48 })
	startupLock := mod.last()

	if err := u.srv.Send(deviceID, helperOffer(t, u, u.signer, "rel-dh-040", "0.4.0", body, releasesig.ComponentDesktopHelper)); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, u.srv, typ) }, 4)
	want := []string{wire.UpdateDownloading, wire.UpdateVerified, wire.UpdateApplying, wire.UpdateSuccess}
	for i, s := range got {
		if s.State != want[i] || s.ReleaseID != "rel-dh-040" || s.ToVersion != "0.4.0" {
			t.Fatalf("etap %d: %+v, oczekiwano %s", i, s, want[i])
		}
	}
	installs, version, installed := h.snapshot()
	if installs != 1 || version != "0.4.0" || string(installed) != string(body) {
		t.Fatalf("instalacja pomocnika: razy=%d wersja=%q zgodny plik=%v", installs, version, string(installed) == string(body))
	}
	// Przy RustDesku jako silniku aktywny menedżer nie jest ruszany: po instalacji pomocnika nie pada nowe hasło zamykające.
	if pw := mod.last(); pw != startupLock {
		t.Fatal("instalacja pomocnika nie może zmieniać hasła klienta RustDesk")
	}
}

// Heartbeat zgłasza włączony silnik i wersję pomocnika osobno od wersji klienta RustDesk.
func TestVersionsReportEngineAndHelper(t *testing.T) {
	u, h, _ := setupHelper(t)
	h.version = "0.4.0"
	u.opts.Cfg.RemoteEngine = config.RemoteEngineWebRTC
	mod := &fakeDesktop{installed: true}
	startWithRemote(t, u.env, mod)

	hb := next(t, u.srv, wire.TypeHeartbeat)
	var p wire.Heartbeat
	if err := json.Unmarshal(hb.D, &p); err != nil {
		t.Fatal(err)
	}
	if p.Versions.RemoteEngine != config.RemoteEngineWebRTC || p.Versions.Helper != "0.4.0" || p.Versions.Remote != "" {
		t.Fatalf("wersje w heartbeacie: %+v", p.Versions)
	}
	if p.Versions.HelperLevel != wire.HelperLevelUser || p.Versions.HelperLevelCfg != wire.HelperLevelUser || p.Versions.HelperToken != "" || p.Versions.HelperFallback {
		t.Fatalf("poziom uprawnień pomocnika w heartbeacie: %+v (domyślnie user, bez tokenu przed pierwszym startem)", p.Versions)
	}
}

// Heartbeat rozróżnia poziom skuteczny (z jakim wystartował silnik), zapisany w konfiguracji i token z ostatniego startu pomocnika,
// żeby panel pokazał rzeczywistość, a nie tylko ustawienie; zapas jest widoczny.
func TestVersionsReportEffectiveLevelConfiguredLevelAndLastToken(t *testing.T) {
	u, h, _ := setupHelper(t)
	h.version = "0.4.3"
	h.level, h.token, h.fallback = wire.HelperLevelIntegrity, "user-fallback", true
	h.session, h.uac = wire.HelperLevelIntegrity, "off"
	u.opts.Cfg.RemoteEngine = config.RemoteEngineWebRTC
	u.opts.Cfg.DesktopHelperLevel = config.DesktopHelperAdmin // zapisane po starcie silnika, działa dopiero po restarcie
	startWithRemote(t, u.env, &fakeDesktop{installed: true})

	hb := next(t, u.srv, wire.TypeHeartbeat)
	var p wire.Heartbeat
	if err := json.Unmarshal(hb.D, &p); err != nil {
		t.Fatal(err)
	}
	v := p.Versions
	if v.HelperLevel != wire.HelperLevelIntegrity || v.HelperLevelCfg != wire.HelperLevelAdmin || v.HelperToken != "user-fallback" || !v.HelperFallback {
		t.Fatalf("wersje w heartbeacie: %+v", v)
	}
	// Podniesienie na czas sesji (zgoda użytkownika) i stan UAC są osobnymi polami od stałego poziomu komputera.
	if v.HelperLevelSession != wire.HelperLevelIntegrity || v.UAC != "off" {
		t.Fatalf("poziom sesji i UAC w heartbeacie: %+v", v)
	}
	// Brak podniesienia jest wysyłany jawnie jako pusty tekst (nie pomijany), żeby serwer mógł zdjąć podniesienie po końcu sesji.
	if !strings.Contains(string(hb.D), `"helper_level_session":"integrity"`) {
		t.Fatalf("surowy heartbeat: %s", hb.D)
	}
}

// Wybór „user” w konfiguracji trafia do serwera w heartbeacie, żeby panel pokazał faktyczny poziom.
func TestVersionsReportHelperLevelUser(t *testing.T) {
	u, h, _ := setupHelper(t)
	h.version = "0.4.0"
	u.opts.Cfg.RemoteEngine = config.RemoteEngineWebRTC
	u.opts.Cfg.DesktopHelperLevel = config.DesktopHelperUser
	h.level = wire.HelperLevelUser
	startWithRemote(t, u.env, &fakeDesktop{installed: true})

	hb := next(t, u.srv, wire.TypeHeartbeat)
	var p wire.Heartbeat
	if err := json.Unmarshal(hb.D, &p); err != nil {
		t.Fatal(err)
	}
	if p.Versions.HelperLevel != wire.HelperLevelUser {
		t.Fatalf("poziom uprawnień pomocnika w heartbeacie: %q", p.Versions.HelperLevel)
	}
}

// Przy włączonym własnym silniku oferta klienta RustDesk (remote_module) jest pomijana: plik RustDeska nie może trafić na
// miejsce pomocnika, którego opakowuje aktywny menedżer.
func TestRemoteModuleOfferIsIgnoredOnWebRTCEngine(t *testing.T) {
	u, _, body := setupHelper(t)
	u.opts.Cfg.RemoteEngine = config.RemoteEngineWebRTC
	mod := &installableDesktop{fakeDesktop: &fakeDesktop{installed: true}}
	startWithRemote(t, u.env, mod)

	if err := u.srv.Send(deviceID, helperOffer(t, u, u.signer, "rel-rd-150", "1.5.0", body, releasesig.ComponentRemoteModule)); err != nil {
		t.Fatal(err)
	}
	// Pomijana oferta nie daje żadnego statusu aktualizacji (ani instalacji).
	deadline := time.After(700 * time.Millisecond)
loop:
	for {
		select {
		case m := <-u.srv.Received:
			if m.T == wire.TypeUpdateStatus {
				t.Fatal("oferta RustDeska przy własnym silniku nie może uruchamiać instalacji")
			}
		case <-deadline:
			break loop
		}
	}
	if installs, _, _ := mod.snapshot(); installs != 0 {
		t.Fatalf("RustDesk zainstalowany mimo własnego silnika: %d", installs)
	}
}

// Bez podniesienia w sesji heartbeat niesie JAWNIE pusty poziom sesji (nie pomija pola), żeby serwer zdjął podniesienie po końcu sesji.
func TestHeartbeatAlwaysCarriesSessionLevelEvenWhenEmpty(t *testing.T) {
	u, h, _ := setupHelper(t)
	h.version = "0.4.3"
	h.level = wire.HelperLevelUser
	u.opts.Cfg.RemoteEngine = config.RemoteEngineWebRTC
	startWithRemote(t, u.env, &fakeDesktop{installed: true})
	hb := next(t, u.srv, wire.TypeHeartbeat)
	if !strings.Contains(string(hb.D), `"helper_level_session":""`) {
		t.Fatalf("pusty poziom sesji ma być wysłany jawnie: %s", hb.D)
	}
}
