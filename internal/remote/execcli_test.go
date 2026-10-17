package remote

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHelperProcess nie jest prawdziwym testem: ExecCLI uruchamia ten plik testowy jako "klienta pulpitu". Rodzic
// zachowuje się jak cichy instalator RustDesk: uruchamia potomka (usługę) dziedziczącego rury wyjścia i kończy z sukcesem.
func TestHelperProcess(t *testing.T) {
	switch os.Getenv("RMM_TEST_HELPER") {
	case "parent":
		child := exec.Command(os.Args[0], "-test.run=TestHelperProcess")
		child.Env = append(os.Environ(), "RMM_TEST_HELPER=child")
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(2)
		}
		_, _ = os.Stdout.WriteString("zainstalowano\n")
		os.Exit(0)
	case "child":
		time.Sleep(15 * time.Second)
		os.Exit(0)
	}
}

// Regresja: instalacja modułu pulpitu wisiała w stanie „applying” bez końca, bo usługa klienta trzymała rurę wyjścia.
func TestExecCLIDoesNotWaitForChildHoldingPipe(t *testing.T) {
	t.Setenv("RMM_TEST_HELPER", "parent")
	start := time.Now()
	out, err := ExecCLI{Exe: os.Args[0], Timeout: 20 * time.Second, WaitDelay: 500 * time.Millisecond}.Run(context.Background(), "-test.run=TestHelperProcess")
	if err != nil {
		t.Fatalf("zakończony sukcesem proces z potomkiem trzymającym rurę nie może dawać błędu: %v", err)
	}
	if !strings.Contains(out, "zainstalowano") {
		t.Fatalf("brak wyjścia procesu: %q", out)
	}
	if d := time.Since(start); d > 8*time.Second {
		t.Fatalf("Run czekał na potomka zamiast wrócić po zakończeniu procesu: %v", d)
	}
}
