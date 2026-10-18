package remote

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"sync"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
)

// pipeProc to pomocnik rozmawiający przez potoki standardowego wejścia i wyjścia, niezależnie od sposobu uruchomienia.
type pipeProc struct {
	stdin io.WriteCloser
	msgs  chan ipc.DesktopMsg
	kill  func()
	wait  func()
	once  sync.Once
	mu    sync.Mutex
	// pid i closeJob ustawia launch_windows (proces w obiekcie zadania KILL_ON_JOB_CLOSE); closeJob zamyka uchwyt zadania, co zabija proces.
	pid      uint32
	closeJob func()
}

func newPipeProc(stdin io.WriteCloser, stdout, stderr io.Reader, kill, wait func(), log *slog.Logger) *pipeProc {
	p := &pipeProc{stdin: stdin, msgs: make(chan ipc.DesktopMsg, 64), kill: kill, wait: wait}
	go func() {
		defer close(p.msgs)
		r := bufio.NewReaderSize(stdout, 1<<20)
		for {
			var m ipc.DesktopMsg
			if err := ipc.ReadLine(r, &m); err != nil {
				break
			}
			p.msgs <- m
		}
		if wait != nil {
			wait()
		}
	}()
	if stderr != nil {
		go func() {
			sc := bufio.NewScanner(stderr)
			sc.Buffer(make([]byte, 64*1024), 64*1024)
			for sc.Scan() {
				if line := strings.TrimSpace(sc.Text()); line != "" {
					log.Warn("pomocnik pulpitu (stderr): " + line)
				}
			}
		}()
	}
	return p
}

func (p *pipeProc) Send(m ipc.DesktopMsg) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return ipc.WriteLine(p.stdin, m)
}

func (p *pipeProc) Messages() <-chan ipc.DesktopMsg { return p.msgs }

func (p *pipeProc) Kill() {
	p.once.Do(func() {
		_ = p.stdin.Close()
		if p.kill != nil {
			p.kill()
		}
	})
}

// launchChild uruchamia pomocnika jako zwykły proces potomny w sesji agenta (tryb rozwojowy: `agent run` bez usługi,
// a także testy). Pod usługą SYSTEM proces trafiłby do sesji 0 bez pulpitu, więc tam używa się launchInUserSession.
func launchChild(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
	cmd := exec.Command(exe)
	hideWindow(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_ = ctx
	return newPipeProc(stdin, stdout, stderr, func() { _ = cmd.Process.Kill() }, func() { _ = cmd.Wait() }, log), nil
}
