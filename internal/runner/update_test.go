package runner_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/internal/fakeserver"
	"github.com/melnykp/pomoc-zdalna-agent/internal/runner"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

type updEnv struct {
	*env
	signer  ssh.Signer
	paths   update.Paths
	body    []byte
	version string
	// artifact obsługuje pobranie pliku; testy podmieniają je, żeby symulować zmanipulowany plik.
	artifact  func(w http.ResponseWriter)
	downloads atomic.Int32
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func setupUpdate(t *testing.T) *updEnv {
	t.Helper()
	e := setup(t, "approved")
	u := &updEnv{env: e, signer: newSigner(t), paths: update.Paths{Root: t.TempDir()}, body: []byte(strings.Repeat("MZ-agent-1.3.0-", 300)), version: "1.3.0"}
	u.artifact = func(w http.ResponseWriter) { _, _ = w.Write(u.body) }
	e.srv.Handle("/v1/releases/artifacts/agent-1.3.0.exe", func(w http.ResponseWriter, r *http.Request) {
		u.downloads.Add(1)
		u.artifact(w)
	})
	e.opts.Versions = wire.Versions{Agent: "1.2.0"}
	e.opts.Update = &runner.UpdateOptions{
		Paths:        u.paths,
		Signers:      []ssh.PublicKey{u.signer.PublicKey()},
		Verify:       func(string, string) error { return nil },
		RequestEvery: time.Hour,
	}
	return u
}

// offer buduje podpisaną ofertę wydania z artefaktem hostowanym przez atrapę.
func (u *updEnv) offer(t *testing.T, signer ssh.Signer, id string) wire.Envelope {
	return u.offerWith(t, signer, id, nil)
}

func (u *updEnv) offerWith(t *testing.T, signer ssh.Signer, id string, mutate func(*releasesig.Manifest)) wire.Envelope {
	t.Helper()
	sum := sha256.Sum256(u.body)
	m := releasesig.Manifest{
		Schema: releasesig.SchemaVersion, Component: releasesig.ComponentAgent, Version: u.version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Artifact:            releasesig.Artifact{URL: u.srv.URL() + "/v1/releases/artifacts/agent-1.3.0.exe", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(u.body))},
		AuthenticodeSubject: "CN=Firma, O=Firma, C=PL", ReleasedAt: "2026-11-20T10:00:00Z",
	}
	if mutate != nil {
		mutate(&m)
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	raw = append(raw, '\n')
	sig, err := releasesig.SignSSHSig(raw, signer)
	if err != nil {
		t.Fatal(err)
	}
	env, err := wire.NewEnvelope(wire.TypeReleaseAvailable, wire.ReleaseAvailable{ReleaseID: id, Component: "agent", Ring: "canary", Version: m.Version, Manifest: string(raw), Signature: string(sig)})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// statuses zbiera kolejne stany update.status od agenta.
func statuses(t *testing.T, recv func(string) wire.Envelope, want int) []wire.UpdateStatus {
	t.Helper()
	var out []wire.UpdateStatus
	for len(out) < want {
		var s wire.UpdateStatus
		if err := recv(wire.TypeUpdateStatus).Decode(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return out
}

func TestSignedOfferIsDownloadedVerifiedAndHandedToWatchdog(t *testing.T) {
	u := setupUpdate(t)
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	if err := u.srv.Send(deviceID, u.offer(t, u.signer, "rel-130")); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, u.srv, typ) }, 3)
	if got[0].State != wire.UpdateDownloading || got[1].State != wire.UpdateVerified || got[2].State != wire.UpdateApplying {
		t.Fatalf("etapy: %+v", got)
	}
	for _, s := range got {
		if s.ReleaseID != "rel-130" || s.FromVersion != "1.2.0" || s.ToVersion != "1.3.0" {
			t.Fatalf("status z błędnymi wersjami: %+v", s)
		}
	}

	req, err := u.paths.ReadRequest()
	if err != nil {
		t.Fatalf("watchdog powinien dostać prośbę: %v", err)
	}
	if req.Version != "1.3.0" || req.FromVersion != "1.2.0" || req.ReleaseID != "rel-130" || req.AuthenticodeSubject != "CN=Firma, O=Firma, C=PL" {
		t.Fatalf("prośba: %+v", req)
	}
	staged, err := os.ReadFile(req.Path)
	if err != nil || string(staged) != string(u.body) || filepath.Dir(req.Path) != u.paths.Staging() {
		t.Fatalf("plik w staging: err=%v len=%d dir=%s", err, len(staged), filepath.Dir(req.Path))
	}
}

func TestOfferSignedByUnknownKeyIsRejectedAndNothingIsDownloaded(t *testing.T) {
	u := setupUpdate(t)
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	if err := u.srv.Send(deviceID, u.offer(t, newSigner(t), "rel-evil")); err != nil {
		t.Fatal(err)
	}
	var s wire.UpdateStatus
	if err := next(t, u.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateFailed || !strings.Contains(s.Error, "weryfikacja oferty") {
		t.Fatalf("status: %+v", s)
	}
	if _, err := u.paths.ReadRequest(); err == nil {
		t.Fatal("niepodpisana oferta nie może dojść do watchdoga")
	}
	if u.downloads.Load() != 0 {
		t.Fatal("nic nie wolno pobierać przed weryfikacją podpisu")
	}
}

func TestTamperedArtifactIsRejectedBeforeWatchdog(t *testing.T) {
	u := setupUpdate(t)
	u.artifact = func(w http.ResponseWriter) { _, _ = w.Write([]byte(strings.Repeat("X", len(u.body)))) } // ten sam rozmiar, inna zawartość
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	if err := u.srv.Send(deviceID, u.offer(t, u.signer, "rel-130")); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, u.srv, typ) }, 2)
	if got[0].State != wire.UpdateDownloading || got[1].State != wire.UpdateFailed {
		t.Fatalf("etapy: %+v", got)
	}
	if _, err := u.paths.ReadRequest(); err == nil {
		t.Fatal("podmieniony plik nie może dojść do watchdoga")
	}
	entries, _ := os.ReadDir(u.paths.Staging())
	if len(entries) != 0 {
		t.Fatalf("staging powinien być pusty: %v", entries)
	}
}

func TestAuthenticodeFailureStopsUpdate(t *testing.T) {
	u := setupUpdate(t)
	u.opts.Update.Verify = func(string, string) error { return update.ErrNoAuthenticode }
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	if err := u.srv.Send(deviceID, u.offer(t, u.signer, "rel-130")); err != nil {
		t.Fatal(err)
	}
	got := statuses(t, func(typ string) wire.Envelope { return next(t, u.srv, typ) }, 2)
	if got[1].State != wire.UpdateFailed || !strings.Contains(got[1].Error, "podpis pliku") {
		t.Fatalf("etapy: %+v", got)
	}
	if _, err := u.paths.ReadRequest(); err == nil {
		t.Fatal("plik bez ważnego podpisu nie może dojść do watchdoga")
	}
	if entries, _ := os.ReadDir(u.paths.Staging()); len(entries) != 0 {
		t.Fatalf("niepodpisany plik powinien zostać usunięty ze staging: %v", entries)
	}
}

func TestKnownBadReleaseIsIgnored(t *testing.T) {
	u := setupUpdate(t)
	if err := u.paths.MarkBad("rel-130"); err != nil {
		t.Fatal(err)
	}
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	if err := u.srv.Send(deviceID, u.offer(t, u.signer, "rel-130")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	drain(u.srv, func(m wire.Envelope) {
		if m.T == wire.TypeUpdateStatus {
			t.Fatalf("wydanie odrzucone wcześniej nie powinno być ponawiane: %s", m.D)
		}
	})
}

func TestOfferForRunningVersionIsIgnored(t *testing.T) {
	u := setupUpdate(t)
	u.opts.Versions = wire.Versions{Agent: "1.3.0"}
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })
	if err := u.srv.Send(deviceID, u.offer(t, u.signer, "rel-130")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(700 * time.Millisecond)
	drain(u.srv, func(m wire.Envelope) {
		if m.T == wire.TypeUpdateStatus {
			t.Fatalf("agent na docelowej wersji nie powinien nic zgłaszać: %s", m.D)
		}
	})
}

func TestAgentConfirmsHealthAndReportsWatchdogResultAfterRestart(t *testing.T) {
	u := setupUpdate(t)
	if err := u.paths.WriteResult(update.Result{ReleaseID: "rel-130", Version: "1.3.0", FromVersion: "1.2.0", State: update.StateRolledBack, Error: "nie wstał", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	start(t, u.env)

	var s wire.UpdateStatus
	if err := next(t, u.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateRolledBack || s.ReleaseID != "rel-130" || s.FromVersion != "1.2.0" || s.ToVersion != "1.3.0" || s.Error != "nie wstał" {
		t.Fatalf("status: %+v", s)
	}
	waitFor(t, "usunięcie wyniku po zgłoszeniu", func() bool {
		_, err := u.paths.ReadResult()
		return err != nil
	})

	h, err := u.paths.ReadHealth()
	if err != nil || h.Phase != update.PhaseConnected || h.Version != "1.2.0" || h.PID != os.Getpid() {
		t.Fatalf("zdrowie: %+v %v", h, err)
	}
	if n := u.paths.StartsSince(time.Now().Add(-time.Minute)); n != 1 {
		t.Fatalf("start powinien zostać odnotowany raz, jest %d", n)
	}
}

func TestUpdateCheckCommandAsksServerForOffer(t *testing.T) {
	u := setupUpdate(t)
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })
	next(t, u.srv, wire.TypeReleaseRequest) // pierwsze zapytanie zaraz po połączeniu

	if err := u.srv.Send(deviceID, cmd(t, "c-upd", wire.CmdUpdateCheck, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	next(t, u.srv, wire.TypeReleaseRequest)
	var res wire.CmdResult
	if err := next(t, u.srv, wire.TypeCmdResult).Decode(&res); err != nil || !res.OK {
		t.Fatalf("wynik: %+v err=%v", res, err)
	}
}

func TestUpdateCheckFailsWhenUpdatesAreDisabled(t *testing.T) {
	e := setup(t, "approved")
	start(t, e)
	waitFor(t, "kanał", func() bool { return e.srv.Connected(deviceID) })
	if err := e.srv.Send(deviceID, cmd(t, "c-upd", wire.CmdUpdateCheck, map[string]any{})); err != nil {
		t.Fatal(err)
	}
	var res wire.CmdResult
	if err := next(t, e.srv, wire.TypeCmdResult).Decode(&res); err != nil || res.OK {
		t.Fatalf("wynik: %+v err=%v", res, err)
	}
}

// drain opróżnia bufor wiadomości, które agent wysłał do atrapy serwera.
func drain(srv *fakeserver.Server, each func(wire.Envelope)) {
	for {
		select {
		case m := <-srv.Received:
			each(m)
		default:
			return
		}
	}
}

// Watchdog zapisuje wynik dopiero po tym, jak zobaczy zdrowie nowej wersji, czyli po jej pierwszym połączeniu.
// Agent musi więc zgłosić wynik także wtedy, gdy plik pojawi się w trakcie działania.
func TestResultWrittenAfterConnectionIsReportedLater(t *testing.T) {
	u := setupUpdate(t)
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })
	next(t, u.srv, wire.TypeHeartbeat)

	if err := u.paths.WriteResult(update.Result{ReleaseID: "rel-130", Version: "1.2.0", FromVersion: "1.1.0", State: update.StateSuccess, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	var s wire.UpdateStatus
	if err := next(t, u.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateSuccess || s.ReleaseID != "rel-130" {
		t.Fatalf("status: %+v", s)
	}
	waitFor(t, "usunięcie zgłoszonego wyniku", func() bool {
		_, err := u.paths.ReadResult()
		return err != nil
	})
}

// Przejęty serwer nie może cofnąć agenta do starszej, poprawnie podpisanej wersji z luką, jeśli agent widział
// wcześniej manifest z progiem bezpieczeństwa.
func TestSecurityFloorFromSignedManifestBlocksLaterDowngradeOffers(t *testing.T) {
	u := setupUpdate(t)
	start(t, u.env)
	waitFor(t, "kanał", func() bool { return u.srv.Connected(deviceID) })

	// Wydanie 1.3.0 wymaga min_version 1.2.5.
	if err := u.srv.Send(deviceID, u.offerWith(t, u.signer, "rel-130", func(m *releasesig.Manifest) { m.MinVersion = "1.2.5" })); err != nil {
		t.Fatal(err)
	}
	statuses(t, func(typ string) wire.Envelope { return next(t, u.srv, typ) }, 3)
	waitFor(t, "zapis progu", func() bool { return u.paths.Floor() == "1.2.5" })
	if err := u.paths.RemoveRequest(); err != nil {
		t.Fatal(err)
	}

	// Serwer podsuwa starsze, ale poprawnie podpisane wydanie 1.2.0 (nowszy numer niż działające 1.2.0 nie ma znaczenia).
	u.opts.Versions = wire.Versions{Agent: "1.2.0"}
	if err := u.srv.Send(deviceID, u.offerWith(t, u.signer, "rel-old", func(m *releasesig.Manifest) { m.Version = "1.2.3" })); err != nil {
		t.Fatal(err)
	}
	var s wire.UpdateStatus
	if err := next(t, u.srv, wire.TypeUpdateStatus).Decode(&s); err != nil {
		t.Fatal(err)
	}
	if s.State != wire.UpdateFailed || !strings.Contains(s.Error, "progu") {
		t.Fatalf("status: %+v", s)
	}
	if _, err := u.paths.ReadRequest(); err == nil {
		t.Fatal("oferta poniżej progu nie może dojść do watchdoga")
	}
	if u.paths.Floor() != "1.2.5" {
		t.Fatalf("próg nie może się zmienić: %q", u.paths.Floor())
	}
}
