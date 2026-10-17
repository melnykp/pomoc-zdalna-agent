package remote

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCLI udaje wiersz poleceń klienta: odpowiedzi wg pierwszego argumentu (i klucza opcji), zapamiętuje wywołania.
type fakeCLI struct {
	mu      sync.Mutex
	calls   []string
	options map[string]string
	idOut   string
	passOut string
	verOut  string
	err     error
}

func (f *fakeCLI) Run(_ context.Context, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, strings.Join(args, " "))
	if f.err != nil {
		return "", f.err
	}
	switch args[0] {
	case "--get-id":
		return f.idOut, nil
	case "--password":
		return f.passOut, nil
	case "--version":
		return f.verOut, nil
	case "--option":
		if len(args) == 2 {
			return f.options[args[1]], nil
		}
		f.options[args[1]] = args[2]
		return "", nil
	}
	return "", errors.New("nieznane polecenie")
}

func newRustDesk(cli *fakeCLI) *RustDesk {
	r := NewRustDesk(`C:\Program Files\RustDesk\rustdesk.exe`, "relay.example.pl", "KLUCZ=")
	r.CLI = cli
	r.exists = func(string) bool { return true }
	r.serviceRunning = func() bool { return true }
	return r
}

func TestIDTakesLastLineOfPortableOutput(t *testing.T) {
	cli := &fakeCLI{idOut: "executing C:\\x\\rustdesk.exe\r\nWindows version: 10.0\r\nis windows7: false\r\n373086536\r\n"}
	id, err := newRustDesk(cli).ID(context.Background())
	if err != nil || id != "373086536" {
		t.Fatalf("id=%q err=%v", id, err)
	}
}

func TestIDRejectsGarbage(t *testing.T) {
	for _, out := range []string{"", "  \n", "to nie jest id!", "Installation and administrative privileges required!"} {
		if id, err := newRustDesk(&fakeCLI{idOut: out}).ID(context.Background()); err == nil {
			t.Errorf("wyjście %q nie powinno dać identyfikatora, dało %q", out, id)
		}
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.Background()
	if err := newRustDesk(&fakeCLI{passOut: "Done!"}).SetPassword(ctx, "Haslo1234"); err != nil {
		t.Fatalf("potwierdzone hasło: %v", err)
	}
	if err := newRustDesk(&fakeCLI{passOut: "Installation and administrative privileges required!"}).SetPassword(ctx, "x"); !errors.Is(err, ErrNeedsAdmin) {
		t.Fatalf("brak uprawnień: %v", err)
	}
	err := newRustDesk(&fakeCLI{passOut: "coś poszło nie tak: TajneHaslo99"}).SetPassword(ctx, "TajneHaslo99")
	if err == nil || strings.Contains(err.Error(), "TajneHaslo99") {
		t.Fatalf("błąd musi istnieć i nie może zawierać hasła: %v", err)
	}
	if err := newRustDesk(&fakeCLI{}).SetPassword(ctx, ""); err == nil {
		t.Fatal("puste hasło musi być odrzucone")
	}
}

func TestEnsureConfigSetsOnlyDifferingOptionsAndOurServer(t *testing.T) {
	cli := &fakeCLI{options: map[string]string{
		"direct-server":        "N", // już dobrze
		"enable-lan-discovery": "Y", // do zmiany
		"key":                  "STARY",
	}}
	r := newRustDesk(cli)
	if err := r.EnsureConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"enable-lan-discovery": "N", "key": "KLUCZ=", "custom-rendezvous-server": "relay.example.pl",
		"relay-server": "relay.example.pl", "verification-method": "use-permanent-password", "approve-mode": "password",
		"allow-remote-config-modification": "N", "direct-server": "N",
	} {
		if cli.options[k] != v {
			t.Errorf("opcja %s = %q, oczekiwano %q", k, cli.options[k], v)
		}
	}
	for _, c := range cli.calls {
		if c == "--option direct-server N" {
			t.Error("opcja z dobrą wartością nie powinna być ponownie zapisywana")
		}
	}

	// Drugie wywołanie nie zmienia niczego: same odczyty (dwa człony: --option i klucz).
	cli.calls = nil
	if err := r.EnsureConfig(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, c := range cli.calls {
		if strings.Count(c, " ") >= 2 {
			t.Errorf("drugie wywołanie nie powinno nic ustawiać, ustawiło: %s", c)
		}
	}
}

func TestEnsureConfigReportsMissingPrivileges(t *testing.T) {
	cli := &fakeCLI{options: map[string]string{}}
	r := newRustDesk(cli)
	for k := range r.desired() {
		cli.options[k] = "Installation and administrative privileges required!"
	}
	if err := r.EnsureConfig(context.Background()); !errors.Is(err, ErrNeedsAdmin) {
		t.Fatalf("EnsureConfig: %v", err)
	}
}

func TestConnectedDetectsConnectionManagerProcess(t *testing.T) {
	r := newRustDesk(&fakeCLI{})
	var got string
	for name, tc := range map[string]struct {
		lines []string
		want  bool
	}{
		"sama usługa":             {[]string{`"C:\Program Files\RustDesk\rustdesk.exe" --service`, `"C:\Program Files\RustDesk\rustdesk.exe" --server`}, false},
		"menedżer połączeń":       {[]string{`"C:\Program Files\RustDesk\rustdesk.exe" --server`, `"C:\Program Files\RustDesk\rustdesk.exe" --cm`}, true},
		"menedżer bez interfejsu": {[]string{`rustdesk.exe --cm-no-ui`}, true},
		"brak procesów":           {nil, false},
		"podobny argument":        {[]string{`rustdesk.exe --cmd`}, false},
	} {
		r.cmdLines = func(image string) ([]string, error) { got = image; return tc.lines, nil }
		ok, err := r.Connected(context.Background())
		if err != nil || ok != tc.want {
			t.Errorf("%s: ok=%v err=%v", name, ok, err)
		}
		if got != "rustdesk.exe" {
			t.Errorf("%s: szukano procesu %q", name, got)
		}
	}
	r.cmdLines = func(string) ([]string, error) { return nil, errors.New("brak dostępu") }
	if _, err := r.Connected(context.Background()); err == nil {
		t.Fatal("błąd odczytu procesów powinien zostać zgłoszony")
	}
}

func TestInstallWaitsForFileAndService(t *testing.T) {
	r := newRustDesk(&fakeCLI{})
	installed := false
	r.exists = func(string) bool { return installed }
	r.serviceRunning = func() bool { return installed }
	r.runInstaller = func(context.Context, string) (string, error) {
		installed = true
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := r.Install(ctx, "instalator.exe"); err != nil {
		t.Fatal(err)
	}
	if !r.Installed() {
		t.Fatal("po instalacji plik powinien istnieć")
	}
}

func TestInstallReportsInstallerFailure(t *testing.T) {
	r := newRustDesk(&fakeCLI{})
	r.runInstaller = func(context.Context, string) (string, error) { return "Failed with error: brak miejsca", nil }
	if err := r.Install(context.Background(), "instalator.exe"); err == nil || !strings.Contains(err.Error(), "brak miejsca") {
		t.Fatalf("błąd instalatora powinien zostać zgłoszony z treścią: %v", err)
	}
	r.runInstaller = func(context.Context, string) (string, error) { return "", errors.New("kod wyjścia 1") }
	if err := r.Install(context.Background(), "instalator.exe"); err == nil {
		t.Fatal("błąd uruchomienia instalatora powinien zostać zgłoszony")
	}
}

func TestBaseNameHandlesWindowsAndUnixPaths(t *testing.T) {
	for in, want := range map[string]string{
		`C:\Program Files\RustDesk\rustdesk.exe`: "rustdesk.exe",
		"/usr/bin/rustdesk":                      "rustdesk",
		"rustdesk.exe":                           "rustdesk.exe",
	} {
		if got := baseName(in); got != want {
			t.Errorf("baseName(%q)=%q, oczekiwano %q", in, got, want)
		}
	}
}

func TestVersionParsesClientOutput(t *testing.T) {
	for out, want := range map[string]string{
		"1.5.0":                    "1.5.0",
		"executing x\r\n1.4.9\r\n": "1.4.9",
		"":                         "",
		"nie wiadomo co":           "",
	} {
		if got := newRustDesk(&fakeCLI{verOut: out}).Version(context.Background()); got != want {
			t.Errorf("wyjście %q: wersja %q, oczekiwano %q", out, got, want)
		}
	}
	if got := newRustDesk(&fakeCLI{err: errors.New("brak pliku")}).Version(context.Background()); got != "" {
		t.Errorf("błąd odczytu powinien dać pustą wersję, jest %q", got)
	}
}
