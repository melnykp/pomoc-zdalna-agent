// Package svc uruchamia agenta jako usługę i obsługuje czynności instalatora wymagające systemu
// (docs/ARCHITECTURE.md). Windows: SCM, podniesienie uprawnień, okno komunikatu. Poza Windows
// pozostaje tryb pierwszoplanowy na potrzeby rozwoju i testów.
package svc

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// ServiceName to nazwa usługi w menedżerze usług Windows.
const ServiceName = "PomocZdalnaAgent"

// WatchdogServiceName to nazwa usługi nadzorcy, który podmienia pliki agenta i robi rollback.
const WatchdogServiceName = "PomocZdalnaWatchdog"

// Runner to proces usługi; Run kończy się, gdy ctx zostanie anulowany.
type Runner interface {
	Run(ctx context.Context) error
}

// RunForeground uruchamia r w bieżącym procesie do czasu SIGINT/SIGTERM.
func RunForeground(r Runner) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return r.Run(ctx)
}
