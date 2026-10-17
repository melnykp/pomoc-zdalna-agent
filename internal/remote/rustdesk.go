package remote

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
)

// ServiceName to nazwa usługi Windows, którą zakłada instalator RustDesk.
const ServiceName = "RustDesk"

// ErrNeedsAdmin: klient pulpitu odmówił zmiany ustawień, bo proces nie ma uprawnień administratora albo klient nie jest
// zainstalowany. Agent działa jako SYSTEM, więc to znaczy błąd instalacji.
var ErrNeedsAdmin = errors.New("remote: klient pulpitu wymaga zainstalowania i uprawnień administratora")

// DefaultOptions to opcje klienta wymuszane przez agenta przy każdym starcie (nazwy kluczy z dokumentacji RustDesk
// i źródeł 1.5.0). Komputer jest dostępny wyłącznie po haśle, bez wykrywania w sieci lokalnej, bez połączeń po
// adresie IP i bez zdalnej zmiany ustawień klienta.
var DefaultOptions = map[string]string{
	"verification-method":              "use-permanent-password", // tylko hasło stałe (my ustawiamy OTP sesji)
	"approve-mode":                     "password",               // bez „kliknij, aby zaakceptować”: klient nie musi być przy komputerze
	"access-mode":                      "full",
	"direct-server":                    "N", // bez połączeń po adresie IP, tylko przez nasz serwer
	"enable-lan-discovery":             "N",
	"allow-remote-config-modification": "N",
	"enable-file-transfer":             "Y",
	"enable-clipboard":                 "Y",
	"enable-audio":                     "Y",
	"enable-keyboard":                  "Y",
	"enable-remote-restart":            "N",
	"allow-auto-disconnect":            "Y", // sesja bez aktywności sama się zamyka
	"auto-disconnect-timeout":          "30",
}

// CLI uruchamia wiersz poleceń klienta pulpitu i zwraca jego wyjście (stdout i stderr razem).
type CLI interface {
	Run(ctx context.Context, args ...string) (string, error)
}

// ExecCLI uruchamia rustdesk.exe jako proces potomny (bez okna konsoli).
type ExecCLI struct {
	Exe     string
	Timeout time.Duration
}

// Run uruchamia klienta z podanymi argumentami. Błąd nie zawiera argumentów, bo mogą nieść hasło.
func (c ExecCLI) Run(ctx context.Context, args ...string) (string, error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.Exe, args...)
	hideWindow(cmd)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("uruchomienie klienta pulpitu: %w", err)
	}
	return text, nil
}

// RustDesk to moduł pulpitu oparty na oficjalnym kliencie RustDesk instalowanym jako usługa.
type RustDesk struct {
	// Exe to ścieżka zainstalowanego rustdesk.exe.
	Exe string
	CLI CLI
	// Host to adres naszego serwera RustDesk (ID i relay), Key to jego klucz publiczny.
	Host, Key string
	// Options nadpisuje DefaultOptions (nil = domyślne).
	Options map[string]string

	// Zależności podmieniane w testach.
	exists         func(path string) bool
	serviceRunning func() bool
	cmdLines       func(image string) ([]string, error)
	runInstaller   func(ctx context.Context, installer string) (string, error)
}

// NewRustDesk tworzy moduł dla zainstalowanego klienta w exe, łączącego się z naszym serwerem.
func NewRustDesk(exe, host, key string) *RustDesk {
	return &RustDesk{
		Exe: exe, CLI: ExecCLI{Exe: exe}, Host: host, Key: key,
		exists:         func(p string) bool { _, err := os.Stat(p); return err == nil },
		serviceRunning: func() bool { return svc.IsRunning(ServiceName) },
		cmdLines:       processCommandLines,
		runInstaller: func(ctx context.Context, installer string) (string, error) {
			return ExecCLI{Exe: installer, Timeout: 5 * time.Minute}.Run(ctx, "--silent-install")
		},
	}
}

// Installed mówi, czy rustdesk.exe istnieje w miejscu instalacji.
func (r *RustDesk) Installed() bool { return r.exists(r.Exe) }

// Running mówi, czy usługa RustDesk działa.
func (r *RustDesk) Running(context.Context) bool { return r.serviceRunning() }

var versionRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// Version zwraca wersję klienta (--version, np. „1.5.0”) albo pusty tekst, gdy odczyt się nie uda.
func (r *RustDesk) Version(ctx context.Context) string {
	out, err := r.CLI.Run(ctx, "--version")
	if err != nil {
		return ""
	}
	if l := lastLine(out); versionRe.MatchString(l) {
		return versionRe.FindString(l)
	}
	return ""
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{4,32}$`)

// ID zwraca identyfikator RustDesk (ostatnia niepusta linia wyjścia --get-id; wcześniejsze to komunikaty rozruchowe).
func (r *RustDesk) ID(ctx context.Context) (string, error) {
	out, err := r.CLI.Run(ctx, "--get-id")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(out, "\r", ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			if !idRe.MatchString(l) {
				return "", fmt.Errorf("remote: nieoczekiwane wyjście --get-id: %q", truncate(l, 80))
			}
			return l, nil
		}
	}
	return "", errors.New("remote: puste wyjście --get-id")
}

// SetPassword ustawia hasło stałe klienta. Klient potwierdza napisem „Done!”.
func (r *RustDesk) SetPassword(ctx context.Context, password string) error {
	if password == "" {
		return errors.New("remote: puste hasło")
	}
	out, err := r.CLI.Run(ctx, "--password", password)
	if err != nil {
		return err
	}
	if strings.Contains(out, "administrative privileges required") {
		return ErrNeedsAdmin
	}
	if !strings.Contains(out, "Done!") {
		// Wyjście nie może zawierać hasła, ale na wszelki wypadek je wycinamy.
		return fmt.Errorf("remote: klient nie potwierdził zmiany hasła: %q", truncate(strings.ReplaceAll(out, password, "***"), 120))
	}
	return nil
}

// desired zwraca komplet opcji, które mają być ustawione: bezpieczne ustawienia i adres naszego serwera.
func (r *RustDesk) desired() map[string]string {
	opts := DefaultOptions
	if r.Options != nil {
		opts = r.Options
	}
	want := map[string]string{}
	for k, v := range opts {
		want[k] = v
	}
	if r.Host != "" {
		want["custom-rendezvous-server"] = r.Host
		want["relay-server"] = r.Host
	}
	if r.Key != "" {
		want["key"] = r.Key
	}
	return want
}

// EnsureConfig porównuje opcje klienta z oczekiwanymi i ustawia tylko te, które się różnią.
func (r *RustDesk) EnsureConfig(ctx context.Context) error {
	want := r.desired()
	keys := make([]string, 0, len(want))
	for k := range want {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		cur, err := r.CLI.Run(ctx, "--option", k)
		if err != nil {
			return fmt.Errorf("odczyt opcji %s: %w", k, err)
		}
		if strings.Contains(cur, "administrative privileges required") {
			return ErrNeedsAdmin
		}
		if lastLine(cur) == want[k] {
			continue
		}
		out, err := r.CLI.Run(ctx, "--option", k, want[k])
		if err != nil {
			return fmt.Errorf("ustawienie opcji %s: %w", k, err)
		}
		if strings.Contains(out, "administrative privileges required") {
			return ErrNeedsAdmin
		}
	}
	return nil
}

// Connected mówi, czy trwa połączenie przychodzące: klient uruchamia wtedy proces menedżera połączeń (rustdesk.exe --cm).
func (r *RustDesk) Connected(context.Context) (bool, error) {
	lines, err := r.cmdLines(baseName(r.Exe))
	if err != nil {
		return false, err
	}
	for _, l := range lines {
		for _, arg := range strings.Fields(l) {
			if arg == "--cm" || strings.HasPrefix(arg, "--cm-") {
				return true, nil
			}
		}
	}
	return false, nil
}

// Install instaluje klienta z pliku instalacyjnego (oficjalny plik RustDesk, wcześniej zweryfikowany przez wywołującego:
// suma SHA-256 i podpis Authenticode z podpisanego manifestu) i czeka, aż pojawi się rustdesk.exe i ruszy usługa.
func (r *RustDesk) Install(ctx context.Context, installer string) error {
	out, err := r.runInstaller(ctx, installer)
	if err != nil {
		return fmt.Errorf("instalacja klienta pulpitu: %w (%s)", err, truncate(out, 200))
	}
	if strings.Contains(out, "Failed with error") {
		return fmt.Errorf("instalacja klienta pulpitu nieudana: %s", truncate(out, 200))
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if r.Installed() && r.serviceRunning() {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("instalacja klienta pulpitu: po 90 s brak pliku albo usługi")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func lastLine(s string) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r", ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
