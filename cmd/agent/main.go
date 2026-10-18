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
	"sync/atomic"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/enroll"
	"github.com/melnykp/pomoc-zdalna-agent/internal/identity"
	"github.com/melnykp/pomoc-zdalna-agent/internal/installer"
	"github.com/melnykp/pomoc-zdalna-agent/internal/logging"
	"github.com/melnykp/pomoc-zdalna-agent/internal/remote"
	"github.com/melnykp/pomoc-zdalna-agent/internal/runner"
	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// version, defaultServer, remoteHost i remoteKey są wstrzykiwane przy budowaniu:
// -ldflags "-X main.version=1.2.3 -X main.defaultServer=https://agent.example.pl -X main.remoteHost=relay.example.pl -X main.remoteKey=KLUCZ".
// Bez remoteHost i remoteKey moduł pulpitu jest wyłączony (polecenia remote.* są odrzucane).
var (
	version       = "0.0.0-dev"
	defaultServer = ""
	remoteHost    = ""
	remoteKey     = ""
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
	case "remote-selftest":
		// Samotest modułu pulpitu na komputerze testowym (jako administrator): instalacja, konfiguracja, sesja z hasłem.
		err = remoteSelfTest(args[1:])
	case "signer-subject":
		// Narzędzie dla ceremonii wydania: podmiot certyfikatu pliku tak, jak widzi go agent (do pola manifestu).
		if len(args) != 2 {
			err = errors.New("użycie: agent signer-subject <plik.exe>")
			break
		}
		var subject string
		if subject, err = update.SignerSubjectOf(args[1]); err == nil {
			fmt.Println(subject)
		}
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
	// Moduł pulpitu tylko w Windows: własny silnik (config remote_engine=webrtc, pomocnik desktop-helper.exe obok agenta)
	// albo przejściowo RustDesk, gdy wkompilowano adres i klucz naszego serwera RustDesk.
	var rr atomic.Pointer[runner.Runner]
	var remoteMgr *remote.Manager
	var module remote.Module
	var helper runner.ComponentInstaller
	if runtime.GOOS == "windows" {
		// Pomocnik własnego silnika jest instalowany (komponent desktop_helper) niezależnie od włączonego silnika, żeby
		// przełączenie na własny silnik (config.set remote_engine + restart) zastało plik już na miejscu.
		eng := remote.NewEngine(remote.DefaultHelperExe(), log)
		eng.OnCandidate = func(sessionID, candidate, sdpMid string) {
			if run := rr.Load(); run != nil {
				run.SendRemoteSignal(wire.RemoteSignal{SessionID: sessionID, Kind: wire.SignalCandidate, Candidate: candidate, SDPMid: sdpMid})
			}
		}
		helper = eng
		switch {
		case cfg.RemoteEngine == config.RemoteEngineWebRTC:
			module = eng
		case remoteHost != "" && remoteKey != "":
			module = remote.NewRustDesk(remote.DefaultExe(), remoteHost, remoteKey)
		}
	}
	if module != nil {
		remoteMgr = remote.NewManager(remote.Options{
			Module: module,
			Log:    log,
			Emit: func(sessionID, state string, stats *wire.RemoteStats) {
				if run := rr.Load(); run != nil {
					run.SendRemoteState(sessionID, state, stats)
				}
			},
		})
	}
	r := runner.New(runner.Options{
		Remote:   remoteMgr,
		Helper:   helper,
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
	rr.Store(r)
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
		// Tryb dla skryptów i testów. Na prawdziwym katalogu danych (bez RMM_DATA_DIR) wymaga administratora, bo inaczej
		// zwykły użytkownik założyłby w ProgramData własny, niezaufany katalog dla usługi działającej jako SYSTEM.
		if runtime.GOOS == "windows" && os.Getenv("RMM_DATA_DIR") == "" && !svc.IsAdmin() {
			return errors.New("--enroll-only na prawdziwym katalogu danych wymaga uprawnień administratora (do prób ustaw RMM_DATA_DIR)")
		}
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
