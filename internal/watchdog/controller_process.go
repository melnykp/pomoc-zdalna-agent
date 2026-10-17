package watchdog

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// ProcessController uruchamia agenta jako proces potomny. Służy do rozwoju, testów i do uruchomień bez
// menedżera usług (Linux, test E2E w CI). W Windows produkcyjnie działa ServiceController.
type ProcessController struct {
	Path string
	Args []string
	Env  []string
	Out  io.Writer

	mu   sync.Mutex
	cmd  *exec.Cmd
	done chan struct{}
}

// Start uruchamia proces, jeśli jeszcze nie działa.
func (c *ProcessController) Start(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.runningLocked() {
		return nil
	}
	cmd := exec.Command(c.Path, c.Args...)
	cmd.Env = append(os.Environ(), c.Env...)
	cmd.Stdout, cmd.Stderr = c.Out, c.Out
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	c.cmd, c.done = cmd, done
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	return nil
}

// Stop prosi proces o zakończenie i po 10 s zabija go. Brak procesu nie jest błędem.
func (c *ProcessController) Stop(ctx context.Context) error {
	c.mu.Lock()
	cmd, done := c.cmd, c.done
	c.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	select {
	case <-done:
		return nil
	default:
	}
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
	} else {
		_ = cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-done:
		return nil
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("proces agenta nie zakończył się")
	}
}

// Running mówi, czy proces działa.
func (c *ProcessController) Running() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runningLocked()
}

func (c *ProcessController) runningLocked() bool {
	if c.cmd == nil {
		return false
	}
	select {
	case <-c.done:
		return false
	default:
		return true
	}
}
