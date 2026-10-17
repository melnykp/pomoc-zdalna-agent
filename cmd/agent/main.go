// Agent „Piotr Melnyk IT - POMOC Zdalna”: usługa na końcówce klienta (docs/ARCHITECTURE.md).
//
// Polecenia:
//
//	agent version
//	agent run                                  tryb pierwszoplanowy (rozwój, diagnostyka)
//	agent service                              punkt wejścia usługi Windows (uruchamia menedżer usług)
//	agent install [--server URL] [--token T]   instalacja: rejestracja, kopia do Program Files, usługa
//	agent uninstall                            usunięcie usługi i plików
//
// Plik pobrany z linku zaproszenia (<Nazwa>-Setup-<token>.exe) uruchomiony bez argumentów
// instaluje się sam, a token czyta z własnej nazwy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/enroll"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/installer"
	"github.com/melnykp/pomoc-zdalna-agent/internal/logging"
	"github.com/melnykp/pomoc-zdalna-agent/internal/runner"
	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// version i defaultServer są wstrzykiwane przy budowaniu:
// -ldflags "-X main.version=1.2.3 -X main.defaultServer=https://agent.example.pl".
var (
	version       = "0.0.0-dev"
	defaultServer = ""
)

const messageTitle = config.ProductName

func main() {
	svc.AttachParentConsole()
	args := os.Args[1:]
	if len(args) == 0 {
		switch {
		case svc.IsWindowsService():
			args = []string{"service"}
		default:
			if _, ok := installer.TokenFromExecutable(); ok {
				args = []string{"install"}
			} else if runtime.GOOS == "windows" {
				// Aplikacja okienkowa nie ma konsoli, więc cichy koniec wyglądałby jak awaria. Zainstalowanej kopii
				// mówimy, że działa w tle. Plik z pulpitu bez zaproszenia prosi o wklejenie kodu.
				if installer.RunningInstalledCopy() {
					svc.Message(messageTitle, "Program jest zainstalowany i działa w tle jako usługa Windows. Nie musisz nic robić.", false)
					os.Exit(0)
				}
				if t, ok := installer.PromptToken(context.Background()); ok {
					args = []string{"install", "--token", t}
				} else {
					svc.Message(messageTitle, "Nie znaleziono zaproszenia. Otwórz link zaproszenia, który dostałeś od inżyniera, i pobierz program ponownie albo wklej kod zaproszenia.", true)
					os.Exit(2)
				}
			}
		}
	}
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	var err error
	switch args[0] {
	case "version":
		fmt.Printf("agent %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
	case "run":
		err = serve(false)
	case "watchdog":
		err = serveWatchdog(false, args[1:])
	case "watchdog-service":
		err = serveWatchdog(true, args[1:])
	case "service":
		err = serve(true)
	case "install":
		err = install(args[1:])
	case "uninstall":
		err = uninstall(args[1:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "błąd:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "użycie: agent <version|run|service|install [--server URL] [--token T]|uninstall>")
}

// serve uruchamia agenta jako usługę (asService) albo w bieżącym procesie.
func serve(asService bool) error {
	cfgPath := config.Path()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("brak poprawnej konfiguracji %s (uruchom „agent install”): %w", cfgPath, err)
	}
	log, closeLog, err := logging.Setup(filepath.Join(config.DataDir(), "logs"), "agent.log", cfg.LogLevel)
	if err != nil {
		return err
	}
	defer closeLog()

	idPath := filepath.Join(config.DataDir(), "identity.bin")
	id, created, err := identity.LoadOrCreate(idPath)
	if err != nil {
		return err
	}
	if created {
		// Klucz zniknął, a konfiguracja pamięta urządzenie zarejestrowane z innym kluczem. Nowy klucz
		// nie przejdzie uwierzytelnienia, więc nie zostawiamy go na dysku.
		_ = os.Remove(idPath)
		return errors.New("brak klucza urządzenia (identity.bin): przywróć plik z kopii albo zarejestruj komputer ponownie")
	}

	signers, err := releasesig.TrustedSigners()
	if err != nil {
		return fmt.Errorf("zły wkompilowany klucz podpisu wydań: %w", err)
	}
	r := runner.New(runner.Options{
		Update:   &runner.UpdateOptions{Paths: update.Paths{Root: config.DataDir()}, Signers: signers},
		Cfg:      cfg,
		CfgPath:  cfgPath,
		Identity: id,
		Log:      log,
		Versions: wire.Versions{Agent: version},
		OnRestart: func() {
			log.Info("restart na polecenie serwera")
			closeLog()
			// Zakończenie bez raportowania stanu „zatrzymana” traktowane jest jako awaria, więc
			// menedżer usług uruchomi usługę ponownie po 5 s.
			os.Exit(3)
		},
		OnRetire: func() {
			log.Warn("wycofanie komputera na polecenie serwera: usuwam agenta")
			if err := installer.Retire(); err != nil {
				log.Error("wycofanie nieudane", "err", err)
			}
		},
	})
	if asService {
		return svc.RunService(svc.ServiceName, r)
	}
	return svc.RunForeground(r)
}

func install(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	server := fs.String("server", "", "adres bramki agenta, np. https://agent.example.pl (domyślnie wkompilowany)")
	token := fs.String("token", "", "token zaproszenia (domyślnie z nazwy pliku instalatora)")
	elevated := fs.Bool("elevated", false, "wewnętrzne: proces uruchomiony z podniesionymi uprawnieniami")
	enrollOnly := fs.Bool("enroll-only", false, "tylko zarejestruj komputer na serwerze: bez usług, bez kopiowania plików i bez uprawnień administratora (skrypty, testy)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	explicitToken := *token != ""
	if *token == "" {
		if t, ok := installer.TokenFromExecutable(); ok {
			*token = t
		}
	}
	if *server == "" {
		*server = defaultServer
	}

	fail := func(err error) error {
		text := "Instalacja nie powiodła się.\n\n" + explain(err)
		svc.Message(messageTitle, text, true)
		return err
	}
	if *token == "" {
		return fail(errors.New("brak tokenu zaproszenia: uruchom plik pobrany z linku albo podaj --token"))
	}
	if *server == "" {
		return fail(errors.New("brak adresu serwera: użyj --server albo programu zbudowanego z wkompilowanym adresem"))
	}

	if *enrollOnly {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		res, err := installer.Enroll(ctx, installer.Params{ServerURL: *server, Token: *token, Version: version, Log: slog.Default()})
		if err != nil {
			return err // bez okna komunikatu: to tryb dla skryptów
		}
		fmt.Println(successText(res))
		return nil
	}

	// Zmienna RMM_DATA_DIR oznacza środowisko deweloperskie albo testowe. Usługa nie dostałaby jej i pracowałaby na
	// innym katalogu danych, więc prawdziwej instalacji (z oknem UAC) wtedy nie robimy.
	if runtime.GOOS == "windows" && os.Getenv("RMM_DATA_DIR") != "" {
		return errors.New("RMM_DATA_DIR jest ustawione: to tryb deweloperski, użyj install --enroll-only albo run")
	}

	if runtime.GOOS == "windows" && !svc.IsAdmin() {
		if *elevated {
			return fail(errors.New("nie udało się uzyskać uprawnień administratora"))
		}
		exe, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		// Token zostaje w nazwie pliku; na linię poleceń trafia tylko wtedy, gdy podano go jawnie.
		a := []string{"install", "--elevated", "--server", *server}
		if explicitToken {
			a = append(a, "--token", *token)
		}
		if err := svc.Elevate(exe, a); err != nil {
			return fail(fmt.Errorf("potrzebna jest zgoda na uruchomienie jako administrator: %w", err))
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := installer.Install(ctx, installer.Params{ServerURL: *server, Token: *token, Version: version, Log: slog.Default()})
	if err != nil {
		return fail(err)
	}

	text := successText(res)
	fmt.Println(text)
	svc.Message(messageTitle, text, false)
	return nil
}

func successText(res installer.Result) string {
	switch {
	case res.Repeated:
		return fmt.Sprintf("Ten komputer jest już zarejestrowany. Usługa została uruchomiona.\n\nKod kontrolny: %s", res.ShortCode)
	case res.Status == "approved":
		return fmt.Sprintf("Gotowe. Komputer jest podłączony do zdalnej pomocy.\n\nKod kontrolny: %s", res.ShortCode)
	default:
		return fmt.Sprintf("Gotowe. Komputer został zgłoszony inżynierowi.\n\nKod kontrolny: %s\n\nInżynier musi go jeszcze zatwierdzić. Jeśli zapyta o kod, podaj mu ten powyżej. To okno możesz zamknąć.", res.ShortCode)
	}
}

// explain zamienia błąd na komunikat zrozumiały dla klienta końcowego.
func explain(err error) string {
	var e *enroll.Error
	if errors.As(err, &e) {
		return enroll.Explain(err)
	}
	return err.Error()
}

func uninstall(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	elevated := fs.Bool("elevated", false, "wewnętrzne: proces uruchomiony z podniesionymi uprawnieniami")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS == "windows" && !svc.IsAdmin() {
		if *elevated {
			return errors.New("nie udało się uzyskać uprawnień administratora")
		}
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		return svc.Elevate(exe, []string{"uninstall", "--elevated"})
	}
	if err := installer.Uninstall(); err != nil {
		return err
	}
	svc.Message(messageTitle, "Program został usunięty z tego komputera.", false)
	return nil
}
