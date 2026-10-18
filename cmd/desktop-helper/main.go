//go:build windows

// desktop-helper to pomocnik pulpitu własnego silnika (docs/adr/0009-wlasny-silnik-pulpitu.md): osobny proces
// uruchamiany przez usługę agenta w sesji zalogowanego użytkownika. Przechwytuje ekran, koduje H.264, rozmawia z widzem
// przez WebRTC i wstrzykuje mysz oraz klawiaturę. Z usługą rozmawia tylko przez standardowe wejście i wyjście; nie zna
// serwera i nic nie nasłuchuje. Zależności WebRTC (pion) są tylko w tym pliku wykonywalnym, nie w usłudze.
//
// Polecenia:
//
//	desktop-helper            pętla sesji (uruchamia usługa)
//	desktop-helper version
//	desktop-helper probe      monitory i karty (diagnostyka na komputerze klienta)
//	desktop-helper consent    okno zgody na podniesienie uprawnień (podproces uruchamiany przez usługę)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/consent"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/helper"
	"github.com/melnykp/pomoc-zdalna-agent/internal/desktop/proc"
)

// version jest wstrzykiwana przy budowaniu: -ldflags "-X main.version=1.2.3".
var version = "0.0.0-dev"

func main() {
	// Na samym początku, zanim cokolwiek załaduje bibliotekę: DLL tylko z System32 i katalogu programu (pomocnik bywa uruchamiany z
	// wysoką integralnością, a PATH i bieżący katalog nie mogą wskazywać na miejsca zapisywalne przez zwykłego użytkownika).
	if err := proc.RestrictDLLSearch(); err != nil {
		fmt.Fprintln(os.Stderr, "ostrzeżenie: SetDefaultDllDirectories:", err)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("desktop-helper %s %s/%s\n", version, runtime.GOOS, runtime.GOARCH)
			return
		case "consent":
			// Okno zgody na podniesienie uprawnień pomocnika: uruchamia je usługa z tokenem o wysokiej integralności (UIPI odrzuca wstrzykiwane wejście z niższej integralności; bariera użyteczności, nie twarda granica,
			// patrz ADR-0009); decyzja idzie na standardowe wyjście. Zobacz internal/desktop/consent.
			if len(os.Args) != 4 {
				fmt.Fprintln(os.Stderr, "użycie: desktop-helper consent <tytuł-base64> <treść-base64>")
				os.Exit(2)
			}
			if err := consent.Run(os.Stdout, os.Args[2], os.Args[3]); err != nil {
				fmt.Fprintln(os.Stderr, "błąd:", err)
				os.Exit(1)
			}
			return
		case "probe":
			if err := helper.Probe(os.Stdout); err != nil {
				fmt.Fprintln(os.Stderr, "błąd:", err)
				os.Exit(1)
			}
			return
		default:
			fmt.Fprintln(os.Stderr, "użycie: desktop-helper [version|probe|consent]")
			os.Exit(2)
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	in, out := helper.Stdio()
	if err := helper.New(in, out, version).Run(ctx); err != nil {
		os.Exit(1)
	}
}
