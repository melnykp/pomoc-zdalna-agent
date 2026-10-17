package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/logging"
	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
	"github.com/melnykp/pomoc-zdalna-agent/internal/update"
	"github.com/melnykp/pomoc-zdalna-agent/internal/watchdog"
)

// serveWatchdog uruchamia nadzorcę agenta: jako usługę Windows (asService) albo w bieżącym procesie.
//
//	agent watchdog [--agent ŚCIEŻKA] [--process]
//
// Domyślnie nadzoruje usługę Windows PomocZdalnaAgent. Z --process (i zawsze poza Windows) uruchamia agenta jako proces
// potomny, co służy rozwojowi i testom bez menedżera usług.
func serveWatchdog(asService bool, args []string) error {
	fs := flag.NewFlagSet("watchdog", flag.ContinueOnError)
	agentPath := fs.String("agent", "", "ścieżka pliku agenta (domyślnie agent.exe obok tego pliku)")
	process := fs.Bool("process", false, "uruchamiaj agenta jako proces potomny zamiast usługi Windows")
	healthTimeout := fs.Duration("health-timeout", 0, "ile czekać na potwierdzenie zdrowia nowej wersji (domyślnie 120 s)")
	poll := fs.Duration("poll", 0, "odstęp pętli nadzoru (domyślnie 2 s)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	log, closeLog, err := logging.Setup(filepath.Join(config.DataDir(), "logs"), "watchdog.log", "info")
	if err != nil {
		return err
	}
	defer closeLog()

	if *agentPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		name := "agent"
		if filepath.Ext(exe) != "" {
			name += filepath.Ext(exe)
		}
		*agentPath = filepath.Join(filepath.Dir(exe), name)
	}

	cfg, err := config.Load(config.Path())
	if err != nil {
		return fmt.Errorf("brak poprawnej konfiguracji %s: %w", config.Path(), err)
	}

	var ctl watchdog.Controller
	if *process || !svc.IsWindowsServiceCapable() {
		ctl = &watchdog.ProcessController{Path: *agentPath, Args: []string{"run"}, Out: os.Stderr}
	} else {
		ctl = watchdog.ServiceController{Name: svc.ServiceName}
	}

	w := watchdog.New(watchdog.Options{
		Paths:           update.Paths{Root: config.DataDir()},
		AgentPath:       *agentPath,
		Controller:      ctl,
		Verify:          update.CheckSignature,
		ServerReachable: watchdog.Reachable(cfg.ServerURL),
		Log:             log,
		HealthTimeout:   *healthTimeout,
		PollInterval:    *poll,
	})
	var r svc.Runner = runFunc(func(ctx context.Context) error {
		err := w.Run(ctx)
		// Proces potomny nie może przeżyć nadzorcy, który go uruchomił (tryb rozwojowy i testy).
		if pc, ok := ctl.(*watchdog.ProcessController); ok {
			_ = pc.Stop(context.Background())
		}
		return err
	})
	if asService {
		return svc.RunService(svc.WatchdogServiceName, r)
	}
	return svc.RunForeground(r)
}

type runFunc func(ctx context.Context) error

func (f runFunc) Run(ctx context.Context) error { return f(ctx) }
