//go:build windows

package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// launchHelper uruchamia pomocnika tam, gdzie jest pulpit: pod usługą (SYSTEM) w sesji zalogowanego użytkownika
// z jego tokenem (WTSQueryUserToken + CreateProcessAsUser, pulpit winsta0\default), a bez usługi (tryb rozwojowy)
// jako zwykły proces potomny.
func launchHelper(ctx context.Context, exe string, log *slog.Logger) (Process, error) {
	if !runningAsSystem() {
		return launchChild(ctx, exe, log)
	}
	return launchInUserSession(exe, log)
}

// runningAsSystem mówi, czy proces działa na koncie LocalSystem (S-1-5-18).
func runningAsSystem() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	return u.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// inheritablePipe tworzy potok, którego jeden koniec dziedziczy proces potomny, a drugi zostaje w usłudze.
func inheritablePipe(childReads bool) (parent, child windows.Handle, err error) {
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	var r, w windows.Handle
	if err := windows.CreatePipe(&r, &w, &sa, 0); err != nil {
		return 0, 0, err
	}
	if childReads {
		parent, child = w, r
	} else {
		parent, child = r, w
	}
	// Koniec usługi nie może trafić do dziecka, bo inaczej EOF po końcu pomocnika nigdy by nie przyszedł.
	if err := windows.SetHandleInformation(parent, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(r)
		windows.CloseHandle(w)
		return 0, 0, err
	}
	return parent, child, nil
}

func launchInUserSession(exe string, log *slog.Logger) (Process, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return nil, ErrNoUserSession
	}
	var tok windows.Token
	if err := windows.WTSQueryUserToken(session, &tok); err != nil {
		// ERROR_NO_TOKEN: sesja konsoli bez zalogowanego użytkownika (ekran logowania).
		if errors.Is(err, windows.ERROR_NO_TOKEN) {
			return nil, ErrNoUserSession
		}
		return nil, fmt.Errorf("token użytkownika sesji %d: %w", session, err)
	}
	defer tok.Close()

	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return nil, fmt.Errorf("środowisko użytkownika: %w", err)
	}
	defer windows.DestroyEnvironmentBlock(env)

	inParent, inChild, err := inheritablePipe(true)
	if err != nil {
		return nil, err
	}
	outParent, outChild, err := inheritablePipe(false)
	if err != nil {
		windows.CloseHandle(inParent)
		windows.CloseHandle(inChild)
		return nil, err
	}
	errParent, errChild, err := inheritablePipe(false)
	if err != nil {
		for _, h := range []windows.Handle{inParent, inChild, outParent, outChild} {
			windows.CloseHandle(h)
		}
		return nil, err
	}

	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desktop, Flags: windows.STARTF_USESTDHANDLES, StdInput: inChild, StdOutput: outChild, StdErr: errChild}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	cmdLine, _ := windows.UTF16PtrFromString(windows.EscapeArg(exe))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	const createNoWindow = 0x08000000
	err = windows.CreateProcessAsUser(tok, nil, cmdLine, nil, nil, true, windows.CREATE_UNICODE_ENVIRONMENT|createNoWindow, env, dir, &si, &pi)
	// Końce dziecka są już odziedziczone (albo niepotrzebne po błędzie).
	for _, h := range []windows.Handle{inChild, outChild, errChild} {
		windows.CloseHandle(h)
	}
	if err != nil {
		for _, h := range []windows.Handle{inParent, outParent, errParent} {
			windows.CloseHandle(h)
		}
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	log.Info("pomocnik pulpitu uruchomiony w sesji użytkownika", "session", session, "pid", pi.ProcessId)

	stdin := os.NewFile(uintptr(inParent), "helper-stdin")
	stdout := os.NewFile(uintptr(outParent), "helper-stdout")
	stderr := os.NewFile(uintptr(errParent), "helper-stderr")
	proc := pi.Process
	kill := func() { _ = windows.TerminateProcess(proc, 1) }
	wait := func() {
		_, _ = windows.WaitForSingleObject(proc, windows.INFINITE)
		windows.CloseHandle(proc)
		stdout.Close()
		stderr.Close()
	}
	return newPipeProc(stdin, stdout, stderr, kill, wait, log), nil
}
