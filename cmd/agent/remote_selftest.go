package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/remote"
	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
)

// remoteSelfTest uruchamia samotest modułu pulpitu na tym komputerze (agent remote-selftest). Przechodzi ten sam kod co
// produkcyjne sesje, więc daje dowód, że instalacja, konfiguracja klienta i sesja z hasłem jednorazowym działają.
//
//	agent remote-selftest [--installer plik.exe] [--host adres] [--key klucz] [--wait 2m]
//
// Wymaga uprawnień administratora. Plik wykonywalny budowany bez -H=windowsgui (konsolowy) wypisuje wynik w oknie; wersja
// okienkowa wypisuje do konsoli rodzica tylko wtedy, gdy wynik jest przekierowany (| Out-Host).
func remoteSelfTest(args []string) error {
	fs := flag.NewFlagSet("remote-selftest", flag.ContinueOnError)
	installer := fs.String("installer", "", "plik instalacyjny RustDesk (potrzebny tylko, gdy klienta jeszcze nie ma)")
	host := fs.String("host", remoteHost, "adres naszego serwera RustDesk (domyślnie wkompilowany)")
	key := fs.String("key", remoteKey, "klucz publiczny naszego serwera RustDesk (domyślnie wkompilowany)")
	wait := fs.Duration("wait", 2*time.Minute, "jak długo czekać na połączenie z drugiego komputera")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return errors.New("samotest modułu pulpitu działa tylko w Windows")
	}
	if !svc.IsAdmin() {
		return errors.New("uruchom jako administrator (PowerShell: „Uruchom jako administrator”)")
	}
	if *host == "" || *key == "" {
		return errors.New("podaj --host i --key naszego serwera RustDesk (albo użyj pliku zbudowanego z -RemoteHost i -RemoteKey)")
	}
	if *installer != "" {
		// Plik instalacyjny musi mieć ważny podpis producenta: nie instalujemy niepodpisanych plików nawet w teście.
		subject, err := update.SignerSubjectOf(*installer)
		if err != nil {
			return fmt.Errorf("plik instalacyjny nie ma ważnego podpisu Authenticode: %w", err)
		}
		fmt.Printf("Podpis pliku instalacyjnego: %s\n", subject)
	}
	mod := remote.NewRustDesk(remote.DefaultExe(), *host, *key)
	ctx, cancel := context.WithTimeout(context.Background(), *wait+5*time.Minute)
	defer cancel()
	return remote.SelfTest(ctx, remote.SelfTestOptions{Module: mod, Installer: *installer, Wait: *wait, Out: os.Stdout})
}
