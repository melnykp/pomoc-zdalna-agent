package update

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

type fixture struct {
	signer   ssh.Signer
	other    ssh.Signer
	body     []byte
	srv      *httptest.Server
	planner  Planner
	manifest releasesig.Manifest
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

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{signer: newSigner(t), other: newSigner(t), body: []byte(strings.Repeat("MZ-nowy-agent-", 200))}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/releases/artifacts/agent-1.3.0.exe", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(f.body) })
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)

	sum := sha256.Sum256(f.body)
	f.manifest = releasesig.Manifest{
		Schema: releasesig.SchemaVersion, Component: releasesig.ComponentAgent, Version: "1.3.0", OS: "windows", Arch: "amd64",
		Artifact:            releasesig.Artifact{URL: f.srv.URL + "/v1/releases/artifacts/agent-1.3.0.exe", SHA256: hex.EncodeToString(sum[:]), Size: int64(len(f.body))},
		AuthenticodeSubject: "CN=Firma, O=Firma, C=PL", ReleasedAt: "2026-11-20T10:00:00Z",
	}
	f.planner = Planner{Signers: []ssh.PublicKey{f.signer.PublicKey()}, CurrentVersion: "1.2.0", ServerURL: f.srv.URL, OS: "windows", Arch: "amd64"}
	return f
}

func (f *fixture) offer(t *testing.T, signer ssh.Signer, mutate func(*releasesig.Manifest)) wire.ReleaseAvailable {
	t.Helper()
	m := f.manifest
	if mutate != nil {
		mutate(&m)
	}
	raw, _ := json.MarshalIndent(m, "", "  ")
	raw = append(raw, '\n')
	sig, err := releasesig.SignSSHSig(raw, signer)
	if err != nil {
		t.Fatal(err)
	}
	return wire.ReleaseAvailable{ReleaseID: "r-1", Component: "agent", Ring: "canary", Version: m.Version, Manifest: string(raw), Signature: string(sig)}
}

func TestPlanAcceptsSignedMatchingOffer(t *testing.T) {
	f := newFixture(t)
	m, err := f.planner.Plan(f.offer(t, f.signer, nil))
	if err != nil || m.Version != "1.3.0" {
		t.Fatalf("m=%+v err=%v", m, err)
	}
}

func TestPlanRejections(t *testing.T) {
	f := newFixture(t)
	cases := map[string]struct {
		offer func() wire.ReleaseAvailable
		want  error
	}{
		"obcy klucz podpisu": {func() wire.ReleaseAvailable { return f.offer(t, f.other, nil) }, releasesig.ErrUntrustedKey},
		"już działająca wersja": {func() wire.ReleaseAvailable {
			return f.offer(t, f.signer, func(m *releasesig.Manifest) { m.Version = "1.2.0" })
		}, ErrUpToDate},
		"zły komponent": {func() wire.ReleaseAvailable {
			o := f.offer(t, f.signer, nil)
			o.Component = "watchdog"
			return o
		}, ErrUnsupportedComponent},
	}
	for name, c := range cases {
		if _, err := f.planner.Plan(c.offer()); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, oczekiwano %v", name, err, c.want)
		}
	}

	// Zmieniony po podpisaniu manifest (serwer nie może podmienić treści).
	o := f.offer(t, f.signer, nil)
	o.Manifest = strings.Replace(o.Manifest, `"1.3.0"`, `"9.9.9"`, 1)
	o.Version = "9.9.9"
	if _, err := f.planner.Plan(o); !errors.Is(err, releasesig.ErrBadSignature) {
		t.Errorf("zmieniony manifest: %v", err)
	}

	for name, mutate := range map[string]func(*releasesig.Manifest){
		"inna platforma":      func(m *releasesig.Manifest) { m.OS = "linux" },
		"inna architektura":   func(m *releasesig.Manifest) { m.Arch = "arm64" },
		"obcy serwer":         func(m *releasesig.Manifest) { m.Artifact.URL = "https://zly.example/v1/releases/artifacts/a.exe" },
		"inna ścieżka":        func(m *releasesig.Manifest) { m.Artifact.URL = f.srv.URL + "/pliki/a.exe" },
		"zapytanie w adresie": func(m *releasesig.Manifest) { m.Artifact.URL += "?x=1" },
	} {
		if _, err := f.planner.Plan(f.offer(t, f.signer, mutate)); err == nil {
			t.Errorf("%s: oferta powinna być odrzucona", name)
		}
	}

	// Wersja w manifeście inna niż oferowana.
	o = f.offer(t, f.signer, nil)
	o.Version = "1.4.0"
	if _, err := f.planner.Plan(o); err == nil {
		t.Error("niezgodna wersja oferty i manifestu powinna być odrzucona")
	}
}

func TestPlanRequiresHTTPSExceptLocalhost(t *testing.T) {
	f := newFixture(t)
	f.planner.ServerURL = "http://agent.example.pl"
	o := f.offer(t, f.signer, func(m *releasesig.Manifest) { m.Artifact.URL = "http://agent.example.pl/v1/releases/artifacts/a.exe" })
	if _, err := f.planner.Plan(o); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http poza localhost musi być odrzucone: %v", err)
	}
}

func TestDownloadVerifiesSizeAndHash(t *testing.T) {
	f := newFixture(t)
	dest := filepath.Join(t.TempDir(), "staging", "agent-1.3.0.exe")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := Download(ctx, f.srv.Client(), f.manifest, dest); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(f.body) {
		t.Fatal("pobrany plik różni się od oryginału")
	}
	if _, err := os.Stat(dest + ".part"); err == nil {
		t.Fatal("plik tymczasowy powinien zniknąć")
	}
}

func TestDownloadRejectsTamperedOrOversizedContent(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for name, mutate := range map[string]func(*releasesig.Manifest){
		"zła suma":        func(m *releasesig.Manifest) { m.Artifact.SHA256 = strings.Repeat("0", 64) },
		"za mały rozmiar": func(m *releasesig.Manifest) { m.Artifact.Size-- },
		"za duży rozmiar": func(m *releasesig.Manifest) { m.Artifact.Size++ },
	} {
		m := f.manifest
		mutate(&m)
		dest := filepath.Join(t.TempDir(), "agent.exe")
		if err := Download(ctx, f.srv.Client(), m, dest); err == nil {
			t.Errorf("%s: pobranie powinno się nie udać", name)
		}
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("%s: do staging nie może trafić niezweryfikowany plik", name)
		}
		if _, err := os.Stat(dest + ".part"); err == nil {
			t.Errorf("%s: plik tymczasowy powinien zostać usunięty", name)
		}
	}
}

func TestDownloadStopsAtDeclaredSizeEvenIfServerSendsMore(t *testing.T) {
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for i := 0; i < 5000; i++ {
			if _, err := w.Write([]byte(strings.Repeat("x", 1024))); err != nil {
				return
			}
		}
	}))
	defer huge.Close()
	m := releasesig.Manifest{Artifact: releasesig.Artifact{URL: huge.URL + "/v1/releases/artifacts/a.exe", SHA256: strings.Repeat("0", 64), Size: 1000}}
	dest := filepath.Join(t.TempDir(), "agent.exe")
	if err := Download(context.Background(), huge.Client(), m, dest); err == nil {
		t.Fatal("serwer przysyłający więcej niż w manifeście musi być odrzucony")
	}
	if _, err := os.Stat(dest + ".part"); err == nil {
		t.Fatal("nie wolno zostawiać części pliku")
	}
}

func TestDownloadHTTPError(t *testing.T) {
	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	m := releasesig.Manifest{Artifact: releasesig.Artifact{URL: notFound.URL + "/x", SHA256: strings.Repeat("0", 64), Size: 10}}
	if err := Download(context.Background(), notFound.Client(), m, filepath.Join(t.TempDir(), "a")); err == nil {
		t.Fatal("404 powinno dać błąd")
	}
}

func TestSubjectsEqual(t *testing.T) {
	if !SubjectsEqual("CN=Firma, O=Firma, C=PL", "C=PL, O=Firma, CN=Firma") {
		t.Error("kolejność składników nie powinna mieć znaczenia")
	}
	if !SubjectsEqual(`CN="Firma, sp. z o.o.", C=PL`, `C=PL, CN="Firma, sp. z o.o."`) {
		t.Error("przecinek w cudzysłowie to jeden składnik")
	}
	if !SubjectsEqual("cn=Firma, c=PL", "CN=Firma, C=PL") {
		t.Error("nazwy atrybutów bez względu na wielkość liter")
	}
	for _, c := range [][2]string{
		{"CN=Firma, C=PL", "CN=Inna, C=PL"},
		{"CN=Firma, C=PL", "CN=Firma"},
		{"CN=Firma", "CN=firma"},
		{"", ""},
		{"nie rdn", "nie rdn"},
	} {
		if SubjectsEqual(c[0], c[1]) {
			t.Errorf("%q i %q nie powinny być równe", c[0], c[1])
		}
	}
}

func TestCheckSignatureHonoursBuildPolicy(t *testing.T) {
	t.Cleanup(func() { RequireAuthenticode = "true" })
	file := filepath.Join(t.TempDir(), "unsigned.exe")
	if err := os.WriteFile(file, []byte("MZ-niepodpisany"), 0o600); err != nil {
		t.Fatal(err)
	}

	RequireAuthenticode = "true"
	if err := CheckSignature(file, "CN=Firma"); err == nil {
		t.Fatal("build produkcyjny nie może przyjąć pliku bez podpisu")
	}
	RequireAuthenticode = "false"
	if err := CheckSignature(file, "CN=Firma"); err != nil {
		t.Fatalf("build rozwojowy pomija Authenticode: %v", err)
	}
}

func TestSubjectsEqualHandlesEscapesAndWindowsSpelling(t *testing.T) {
	if !SubjectsEqual(`CN=Firma\, sp. z o.o.,C=PL`, `C=PL, CN="Firma, sp. z o.o."`) {
		t.Error("ucieczka przecinka i cudzysłów to ta sama wartość")
	}
	if !SubjectsEqual("CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US", "C=US, S=Washington, L=Redmond, O=Microsoft Corporation, CN=Microsoft Corporation") {
		t.Error("S i ST oznaczają to samo")
	}
}

func TestFloorBlocksOlderSignedOfferAndNeverDecreases(t *testing.T) {
	f := newFixture(t)
	p := Paths{Root: t.TempDir()}
	f.planner.CurrentVersion = "1.2.0"

	// Cofanie jest zabronione zawsze, także bez progu: starsza, poprawnie podpisana wersja mogłaby mieć lukę.
	older := f.offer(t, f.signer, func(m *releasesig.Manifest) { m.Version = "1.1.0" })
	if _, err := f.planner.Plan(older); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("starsza oferta niż uruchomiona wersja powinna być odrzucona: %v", err)
	}

	// Próg działa dla komputera, który wrócił do starszej wersji (rollback): działa 1.0.0, a po zobaczeniu wydania 1.3.0
	// z progiem 1.2.5 niższe wersje są zakazane.
	f.planner.CurrentVersion = "1.0.0"
	if err := p.RaiseFloor("1.2.5"); err != nil {
		t.Fatal(err)
	}
	f.planner.Floor = p.Floor()
	if f.planner.Floor != "1.2.5" {
		t.Fatalf("próg: %q", f.planner.Floor)
	}
	if _, err := f.planner.Plan(older); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("starsza oferta poniżej progu: %v", err)
	}
	if _, err := f.planner.Plan(f.offer(t, f.signer, func(m *releasesig.Manifest) { m.Version = "1.2.5" })); err != nil {
		t.Fatalf("wersja równa progowi jest dozwolona: %v", err)
	}
	if _, err := f.planner.Plan(f.offer(t, f.signer, nil)); err != nil {
		t.Fatalf("wersja powyżej progu jest dozwolona: %v", err)
	}

	// Próg nie maleje, nawet gdy ktoś pokaże manifest z niższym.
	if err := p.RaiseFloor("1.0.0"); err != nil || p.Floor() != "1.2.5" {
		t.Fatalf("próg nie może maleć: %q %v", p.Floor(), err)
	}
	if err := p.RaiseFloor("1.4.0"); err != nil || p.Floor() != "1.4.0" {
		t.Fatalf("próg rośnie: %q %v", p.Floor(), err)
	}
	if err := p.RaiseFloor(""); err != nil || p.Floor() != "1.4.0" {
		t.Fatalf("pusty próg niczego nie zmienia: %q %v", p.Floor(), err)
	}
}

func TestOfferEqualToRunningVersionIsUpToDateEvenBelowFloor(t *testing.T) {
	f := newFixture(t)
	f.planner.CurrentVersion = "1.3.0"
	f.planner.Floor = "1.5.0" // próg z nieudanej aktualizacji, wyższy niż działająca wersja
	if _, err := f.planner.Plan(f.offer(t, f.signer, nil)); !errors.Is(err, ErrUpToDate) {
		t.Fatalf("działająca wersja to nie błąd progu: %v", err)
	}
}
