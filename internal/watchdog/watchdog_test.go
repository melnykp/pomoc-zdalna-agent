package watchdog

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
)

// fakeAgent udaje agenta: „plik wykonywalny” to tekst „version=1.2.0 behavior=ok”, a Start zachowuje się tak,
// jak ten plik każe. Dzięki temu cała logika podmiany i rollbacku jest testowana na prawdziwych plikach.
type fakeAgent struct {
	mu        sync.Mutex
	paths     update.Paths
	agentPath string
	running   bool
	starts    []string
	failStop  bool
	failStart bool
}

func (f *fakeAgent) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStop {
		return errors.New("usługa nie chce się zatrzymać")
	}
	f.running = false
	return nil
}

func (f *fakeAgent) Running() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

func (f *fakeAgent) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failStart {
		return errors.New("start nie powiódł się")
	}
	raw, err := os.ReadFile(f.agentPath)
	if err != nil {
		return err
	}
	var version, behavior string
	for _, part := range strings.Fields(string(raw)) {
		k, v, _ := strings.Cut(part, "=")
		switch k {
		case "version":
			version = v
		case "behavior":
			behavior = v
		}
	}
	f.starts = append(f.starts, version+"/"+behavior)
	_ = f.paths.RecordStart(time.Now())
	switch behavior {
	case "ok":
		f.running = true
		_ = f.paths.WriteHealth(update.Health{Version: version, Phase: update.PhaseConnected, PID: 1, At: time.Now()})
	case "noconnect":
		f.running = true
		_ = f.paths.WriteHealth(update.Health{Version: version, Phase: update.PhaseStarted, PID: 1, At: time.Now()})
	case "crash":
		f.running = false
	}
	return nil
}

type env struct {
	w        *Watchdog
	f        *fakeAgent
	paths    update.Paths
	agent    string
	reach    bool
	verified []string
	verifyFn func(path, subject string) error
	signer   ssh.Signer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	e := &env{paths: update.Paths{Root: filepath.Join(root, "data")}, agent: filepath.Join(root, "bin", "agent.exe")}
	if err := os.MkdirAll(filepath.Dir(e.agent), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(e.paths.Staging(), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.agent, []byte("version=1.2.0 behavior=ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.f = &fakeAgent{paths: e.paths, agentPath: e.agent, running: true}
	e.signer = newSigner(t)
	e.w = New(Options{
		Signers:    []ssh.PublicKey{e.signer.PublicKey()},
		Paths:      e.paths,
		AgentPath:  e.agent,
		Controller: e.f,
		Verify: func(path, subject string) error {
			e.verified = append(e.verified, subject)
			if e.verifyFn != nil {
				return e.verifyFn(path, subject)
			}
			return nil
		},
		ServerReachable: func(context.Context) bool { return e.reach },
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		HealthTimeout:   600 * time.Millisecond,
		PollInterval:    40 * time.Millisecond,
		CrashWindow:     10 * time.Minute,
		CrashLimit:      3,
	})
	return e
}

// stage kładzie „nową wersję” w staging i zwraca prośbę o jej podmianę.
func (e *env) stage(t *testing.T, version, behavior string) update.Request {
	t.Helper()
	body := []byte(fmt.Sprintf("version=%s behavior=%s", version, behavior))
	path := filepath.Join(e.paths.Staging(), "agent-"+version+".exe")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	req := update.Request{
		ReleaseID: "rel-" + version, Component: "agent", Version: version, FromVersion: "1.2.0",
		Path: path, SHA256: hex.EncodeToString(sum[:]), Size: int64(len(body)), AuthenticodeSubject: "CN=Firma", RequestedAt: time.Now(),
	}
	e.sign(t, &req, e.signer)
	return req
}

func newSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// sign dołącza do prośby manifest zgodny z jej polami, podpisany podanym kluczem (tak jak robi to agent z oferty).
func (e *env) sign(t *testing.T, req *update.Request, signer ssh.Signer) {
	t.Helper()
	m := releasesig.Manifest{
		Schema: 1, Component: req.Component, Version: req.Version, OS: runtime.GOOS, Arch: runtime.GOARCH,
		Artifact:            releasesig.Artifact{URL: "https://srv.example/v1/releases/artifacts/agent.exe", SHA256: req.SHA256, Size: req.Size},
		AuthenticodeSubject: req.AuthenticodeSubject, ReleasedAt: "2026-10-17T10:00:00Z",
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := releasesig.SignSSHSig(raw, signer)
	if err != nil {
		t.Fatal(err)
	}
	req.Manifest, req.Signature = string(raw), string(sig)
}

func (e *env) installed(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(e.agent)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestSuccessfulUpdateKeepsPrevAndReportsSuccess(t *testing.T) {
	e := newEnv(t)
	req := e.stage(t, "1.3.0", "ok")
	res := e.w.Apply(context.Background(), req)

	if res.State != update.StateSuccess || res.Error != "" {
		t.Fatalf("wynik: %+v", res)
	}
	if e.installed(t) != "version=1.3.0 behavior=ok" {
		t.Fatalf("zainstalowano: %q", e.installed(t))
	}
	if prev, _ := os.ReadFile(e.agent + ".prev"); string(prev) != "version=1.2.0 behavior=ok" {
		t.Fatalf("poprzednia wersja powinna czekać w .prev: %q", prev)
	}
	if _, err := os.Stat(req.Path); err == nil {
		t.Fatal("plik ze staging powinien zniknąć")
	}
	if _, err := e.paths.ReadRequest(); !errors.Is(err, update.ErrNone) {
		t.Fatal("prośba powinna zostać usunięta")
	}
	if got, err := e.paths.ReadResult(); err != nil || got.State != update.StateSuccess {
		t.Fatalf("wynik dla agenta: %+v %v", got, err)
	}
	if last, err := e.paths.ReadLastUpdate(); err != nil || last.Version != "1.3.0" || last.FromVersion != "1.2.0" {
		t.Fatalf("ostatnia podmiana: %+v %v", last, err)
	}
	if len(e.verified) != 1 || e.verified[0] != "CN=Firma" {
		t.Fatalf("watchdog powinien sam sprawdzić podpis pliku: %v", e.verified)
	}
}

func TestBrokenNewVersionIsRolledBackAndMarkedBad(t *testing.T) {
	e := newEnv(t)
	e.reach = true // serwer osiągalny, więc brak połączenia obciąża nową wersję
	req := e.stage(t, "1.3.0", "noconnect")
	res := e.w.Apply(context.Background(), req)

	if res.State != update.StateRolledBack {
		t.Fatalf("wynik: %+v", res)
	}
	if e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatalf("po rollbacku powinna działać stara wersja: %q", e.installed(t))
	}
	if bad, _ := os.ReadFile(e.agent + ".bad"); string(bad) != "version=1.3.0 behavior=noconnect" {
		t.Fatalf("wadliwa wersja powinna być odłożona do .bad: %q", bad)
	}
	if !e.paths.IsBad("rel-1.3.0") {
		t.Fatal("wydanie powinno trafić na listę odrzuconych")
	}
	if want := []string{"1.3.0/noconnect", "1.2.0/ok"}; strings.Join(e.f.starts, ",") != strings.Join(want, ",") {
		t.Fatalf("kolejność startów: %v", e.f.starts)
	}
	if !e.f.Running() {
		t.Fatal("po rollbacku agent powinien działać")
	}
}

func TestCrashingNewVersionIsRolledBack(t *testing.T) {
	e := newEnv(t)
	res := e.w.Apply(context.Background(), e.stage(t, "1.3.0", "crash"))
	if res.State != update.StateRolledBack || e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatalf("res=%+v installed=%q", res, e.installed(t))
	}
}

func TestOfflineMachineDoesNotBlameTheNewVersion(t *testing.T) {
	e := newEnv(t)
	e.reach = false // komputer nie dosięga serwera
	req := e.stage(t, "1.3.0", "noconnect")
	res := e.w.Apply(context.Background(), req)

	if res.State != update.StateSuccess {
		t.Fatalf("proces wstał, a serwer jest nieosiągalny dla całego komputera, więc nowa wersja zostaje: %+v", res)
	}
	if e.installed(t) != "version=1.3.0 behavior=noconnect" {
		t.Fatalf("zainstalowano: %q", e.installed(t))
	}
	if e.paths.IsBad("rel-1.3.0") {
		t.Fatal("wydanie nie może trafić na listę odrzuconych z powodu braku sieci")
	}
}

func TestInvalidFilesAreRejectedWithoutTouchingTheAgent(t *testing.T) {
	cases := map[string]func(e *env, r *update.Request){
		"zła suma":       func(e *env, r *update.Request) { r.SHA256 = strings.Repeat("0", 64) },
		"zły rozmiar":    func(e *env, r *update.Request) { r.Size++ },
		"obcy komponent": func(e *env, r *update.Request) { r.Component = "watchdog" },
		"poza staging": func(e *env, r *update.Request) {
			outside := filepath.Join(filepath.Dir(e.agent), "x.exe")
			_ = os.WriteFile(outside, []byte("version=9 behavior=ok"), 0o755)
			r.Path = outside
		},
		"ucieczka ścieżką": func(e *env, r *update.Request) {
			r.Path = filepath.Join(e.paths.Staging(), "..", "..", "bin", "agent.exe")
		},
		"brak wersji": func(e *env, r *update.Request) { r.Version = "" },
		"zły podpis Authenticode": func(e *env, r *update.Request) {
			e.verifyFn = func(string, string) error { return errors.New("podpis nieważny") }
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			req := e.stage(t, "1.3.0", "ok")
			mutate(e, &req)
			res := e.w.Apply(context.Background(), req)
			if res.State != update.StateFailed {
				t.Fatalf("wynik: %+v", res)
			}
			if e.installed(t) != "version=1.2.0 behavior=ok" {
				t.Fatalf("plik agenta nie może zostać ruszony: %q", e.installed(t))
			}
			if len(e.f.starts) != 0 || !e.f.Running() {
				t.Fatalf("agent nie powinien być restartowany (starty %v)", e.f.starts)
			}
			if _, err := os.Stat(e.agent + ".prev"); err == nil {
				t.Fatal("nie powinno powstać .prev")
			}
		})
	}
}

func TestStopFailureLeavesAgentIntactAndRestarts(t *testing.T) {
	e := newEnv(t)
	e.f.failStop = true
	res := e.w.Apply(context.Background(), e.stage(t, "1.3.0", "ok"))
	if res.State != update.StateFailed || e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatalf("res=%+v installed=%q", res, e.installed(t))
	}
}

func TestTickAppliesRequestFileAndRestartsStoppedAgent(t *testing.T) {
	e := newEnv(t)
	e.f.running = false
	e.w.Tick(context.Background())
	if !e.f.Running() || len(e.f.starts) != 1 {
		t.Fatalf("zatrzymany agent powinien zostać uruchomiony: %v", e.f.starts)
	}

	req := e.stage(t, "1.3.0", "ok")
	if err := e.paths.WriteRequest(req); err != nil {
		t.Fatal(err)
	}
	e.w.Tick(context.Background())
	if e.installed(t) != "version=1.3.0 behavior=ok" {
		t.Fatalf("prośba z pliku powinna zostać wykonana: %q", e.installed(t))
	}
}

func TestTickDropsUnreadableRequest(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(e.paths.State(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.paths.State(), "update-request.json"), []byte("{to nie json"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.w.Tick(context.Background())
	if _, err := e.paths.ReadRequest(); !errors.Is(err, update.ErrNone) {
		t.Fatal("uszkodzona prośba powinna zostać usunięta, żeby nie blokować pętli")
	}
}

func TestCrashLoopAfterUpdateRollsBackToPrev(t *testing.T) {
	e := newEnv(t)
	req := e.stage(t, "1.3.0", "ok")
	if res := e.w.Apply(context.Background(), req); res.State != update.StateSuccess {
		t.Fatalf("podmiana: %+v", res)
	}
	_ = e.paths.RemoveResult()

	// Nowa wersja zaczyna się wykrzaczać: trzy starty w ciągu kilku minut.
	now := time.Now()
	for i := 0; i < 3; i++ {
		_ = e.paths.RecordStart(now.Add(-time.Duration(3-i) * time.Minute))
	}
	e.w.Tick(context.Background())

	if e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatalf("po pętli awarii powinna wrócić poprzednia wersja: %q", e.installed(t))
	}
	if !e.paths.IsBad("rel-1.3.0") {
		t.Fatal("wydanie powinno trafić na listę odrzuconych")
	}
	res, err := e.paths.ReadResult()
	if err != nil || res.State != update.StateRolledBack || res.Version != "1.3.0" || !strings.Contains(res.Error, "pętl") {
		t.Fatalf("agent powinien dostać wynik rollbacku: %+v %v", res, err)
	}
	if _, err := e.paths.ReadLastUpdate(); !errors.Is(err, update.ErrNone) {
		t.Fatal("okno rollbacku powinno się zamknąć")
	}
}

func TestCrashLoopWithoutRecentUpdateDoesNotRollBack(t *testing.T) {
	e := newEnv(t)
	now := time.Now()
	for i := 0; i < 5; i++ {
		_ = e.paths.RecordStart(now.Add(-time.Duration(i) * time.Minute))
	}
	e.w.Tick(context.Background())
	if e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatal("bez świeżej aktualizacji nie ma do czego wracać")
	}
	if _, err := os.Stat(e.agent + ".bad"); err == nil {
		t.Fatal("nic nie powinno trafić do .bad")
	}
}

func TestCrashLoopOlderThanWindowAfterUpdateIsIgnored(t *testing.T) {
	e := newEnv(t)
	e.w.o.CrashRollbackWithin = time.Hour
	if err := e.paths.WriteLastUpdate(update.LastUpdate{ReleaseID: "rel-1.3.0", Version: "1.3.0", FromVersion: "1.2.0", At: time.Now().Add(-48 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.agent+".prev", []byte("version=1.1.0 behavior=ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_ = e.paths.RecordStart(time.Now().Add(-time.Duration(i) * time.Minute))
	}
	e.w.Tick(context.Background())
	if e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatal("po 48 godzinach awarie nie są już winą aktualizacji")
	}
}

func TestRollbackWithoutPrevReportsFailure(t *testing.T) {
	e := newEnv(t)
	e.reach = true
	req := e.stage(t, "1.3.0", "noconnect")
	// Psujemy scenariusz: .prev znika po podmianie, więc rollback nie ma do czego wracać.
	e.f.mu.Lock()
	e.f.mu.Unlock()
	go func() {
		for i := 0; i < 200; i++ {
			if _, err := os.Stat(e.agent + ".prev"); err == nil {
				_ = os.Remove(e.agent + ".prev")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	res := e.w.Apply(context.Background(), req)
	if res.State != update.StateFailed || !strings.Contains(res.Error, "rollback") {
		t.Fatalf("wynik: %+v", res)
	}
}

func TestInstalledFileIsExecutableAfterSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows nie ma bitu wykonywania")
	}
	e := newEnv(t)
	req := e.stage(t, "1.3.0", "ok") // staging tworzy pliki z trybem 0600, jak pobieranie
	if res := e.w.Apply(context.Background(), req); res.State != update.StateSuccess {
		t.Fatalf("podmiana: %+v", res)
	}
	st, err := os.Stat(e.agent)
	if err != nil || st.Mode().Perm()&0o111 == 0 {
		t.Fatalf("nowa wersja musi być wykonywalna: %v %v", st, err)
	}
}

func TestRunWritesWatchdogVersionForTheAgent(t *testing.T) {
	e := newEnv(t)
	e.w.o.Version = "1.2.0"
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_ = e.w.Run(ctx)

	info, err := e.paths.ReadWatchdog()
	if err != nil {
		t.Fatalf("watchdog nie zapisał znacznika: %v", err)
	}
	if info.Version != "1.2.0" || info.PID != os.Getpid() || info.At.IsZero() {
		t.Fatalf("zły znacznik watchdoga: %+v", info)
	}
}

func TestWatchdogWithoutVersionWritesNothing(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	_ = e.w.Run(ctx)
	if _, err := e.paths.ReadWatchdog(); !errors.Is(err, update.ErrNone) {
		t.Fatalf("bez wersji nie powinno być znacznika, jest: %v", err)
	}
}

// Prośba w katalogu stanu nie dowodzi niczego sama z siebie: bez manifestu podpisanego zaufanym kluczem watchdog nie
// podmienia pliku, nawet gdy suma i rozmiar zgadzają się z podstawionym plikiem.
func TestRequestWithoutValidManifestSignatureIsRefused(t *testing.T) {
	cases := map[string]func(e *env, req *update.Request){
		"manifest podpisany obcym kluczem": func(e *env, req *update.Request) { e.sign(t, req, newSigner(t)) },
		"brak manifestu i podpisu":         func(e *env, req *update.Request) { req.Manifest, req.Signature = "", "" },
		"inna suma w prośbie niż w manifeście": func(e *env, req *update.Request) {
			req.SHA256 = strings.Repeat("a", 64)
		},
		"inna wersja w prośbie niż w manifeście": func(e *env, req *update.Request) { req.Version = "9.9.9" },
		"inny podmiot Authenticode w prośbie":    func(e *env, req *update.Request) { req.AuthenticodeSubject = "CN=Intruz" },
		"zmieniony rozmiar w prośbie":            func(e *env, req *update.Request) { req.Size++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			req := e.stage(t, "1.3.0", "ok")
			mutate(e, &req)
			res := e.w.Apply(context.Background(), req)
			if res.State != update.StateFailed {
				t.Fatalf("prośba powinna zostać odrzucona: %+v", res)
			}
			if e.installed(t) != "version=1.2.0 behavior=ok" {
				t.Fatalf("plik agenta nie może się zmienić: %q", e.installed(t))
			}
		})
	}
}

func TestWatchdogWithoutTrustedSignersRefusesEverySwap(t *testing.T) {
	e := newEnv(t)
	e.w.o.Signers = nil
	req := e.stage(t, "1.3.0", "ok")
	res := e.w.Apply(context.Background(), req)
	if res.State != update.StateFailed || !strings.Contains(res.Error, "klucz") {
		t.Fatalf("bez kluczy podpisu podmiana powinna być odrzucona: %+v", res)
	}
	if e.installed(t) != "version=1.2.0 behavior=ok" {
		t.Fatalf("plik agenta nie może się zmienić: %q", e.installed(t))
	}
}
