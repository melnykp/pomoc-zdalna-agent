//go:build windows

package remote

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// launchHelper uruchamia pomocnika tam, gdzie jest pulpit: pod usługą (SYSTEM) w sesji zalogowanego użytkownika
// z tokenem wybranym wg poziomu (WTSQueryUserToken + CreateProcessAsUser, pulpit winsta0\default), a bez usługi (tryb
// rozwojowy) jako zwykły proces potomny. level (config.DesktopHelper*) wybiera: zwykły token użytkownika z wysoką integralnością
// bez grupy Administratorzy (domyślnie), token administratora tego samego użytkownika albo token średniej integralności.
// onChoice dostaje opis wybranego tokenu (do raportu dla serwera), gdy pomocnik startuje pod usługą.
func launchHelper(ctx context.Context, exe string, log *slog.Logger, level string, onChoice func(TokenChoice)) (Process, error) {
	if !runningAsSystem() {
		log.Info("pomocnik pulpitu uruchamiany jako zwykły proces potomny (agent nie działa jako usługa SYSTEM), poziom uprawnień z konfiguracji nie ma zastosowania", "level", level)
		return launchChild(ctx, exe, log)
	}
	return launchInUserSession(exe, log, level, onChoice)
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

func launchInUserSession(exe string, log *slog.Logger, level string, onChoice func(TokenChoice)) (Process, error) {
	session := windows.WTSGetActiveConsoleSessionId()
	if session == 0xFFFFFFFF {
		return nil, ErrNoUserSession
	}
	if session == 0 {
		// Sesja 0 to sesja usług: nie ma w niej pulpitu użytkownika i nie wolno w niej uruchamiać pomocnika.
		return nil, fmt.Errorf("%w: sesja konsoli to sesja 0 (usług)", ErrNoUserSession)
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

	procTok, choice, done, err := chooseHelperToken(tok, session, level, realTokenOps())
	if err != nil {
		// Nie wolno oddać pomocnikowi tokenu, którego nie umiemy zweryfikować albo odchudzić: pomocnik nie startuje.
		log.Error("pomocnik pulpitu NIE wystartuje: nie udało się przygotować bezpiecznego tokenu", "session", session, "level", level, "err", err)
		return nil, fmt.Errorf("token pomocnika pulpitu: %w", err)
	}
	defer done()
	attrs := []any{"session", session, "level", choice.Level, "token", choice.Kind, "elevation", choice.Elevation, "integrity", choice.Integrity, "admin_group", choice.AdminGroup, "lowered", choice.Lowered, "reason", choice.Reason}
	if choice.Fallback {
		// Miało być więcej (integralność wysoka / administrator), a pomocnik dostaje token średniej integralności: wejście do okien
		// administratora będzie blokowane (UIPI).
		log.Warn("pomocnik pulpitu NIE dostał wybranego poziomu uprawnień, uruchamiam z tokenem średniej integralności (zapas)", attrs...)
	} else {
		log.Info("token pomocnika pulpitu wybrany", attrs...)
	}
	if onChoice != nil {
		onChoice(choice)
	}
	// Środowisko: dla tokenów podniesionych (integralność wysoka) minimalne, systemowe, bez PATH i zmiennych użytkownika, które
	// napastnik o niższej integralności mógłby podstawić; dla tokenu średniej integralności, jak dotąd, z tokenu użytkownika.
	return startWithToken(procTok, tok, usesMinimalEnv(choice.Kind), session, exe, log)
}

// usesMinimalEnv mówi, czy token tego rodzaju ma integralność wysoką i dlatego dostaje minimalne środowisko.
func usesMinimalEnv(kind string) bool {
	switch kind {
	case TokenIntegrity, TokenAdminLinked, TokenAdminFull:
		return true
	}
	return false
}

// minimalEnvBlock buduje blok środowiska tylko z tym, czego potrzebuje pomocnik i system: katalog Windows, systemowy PATH,
// systemowy TEMP. Bez profilu użytkownika (APPDATA, USERPROFILE, HOME), bez PATH użytkownika i bez zmiennych sterujących
// środowiskami uruchomieniowymi (GODEBUG, COMPlus_*, DOTNET_*, LD_*…). Pomocnik niczego nie czyta ani nie zapisuje w profilu.
func minimalEnvBlock() ([]uint16, error) {
	win, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return nil, fmt.Errorf("katalog Windows: %w", err)
	}
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, fmt.Errorf("katalog systemowy: %w", err)
	}
	temp := filepath.Join(win, "Temp")
	vars := []string{
		"ComSpec=" + filepath.Join(sys, "cmd.exe"),
		"PATH=" + sys + ";" + win,
		"SystemDrive=" + filepath.VolumeName(win),
		"SystemRoot=" + win,
		"TEMP=" + temp,
		"TMP=" + temp,
		"windir=" + win,
	}
	// Blok środowiska powinien być posortowany bez uwzględniania wielkości liter.
	sort.Slice(vars, func(i, j int) bool { return strings.ToUpper(vars[i]) < strings.ToUpper(vars[j]) })
	var block []uint16
	for _, v := range vars {
		u, err := windows.UTF16FromString(v)
		if err != nil {
			return nil, err
		}
		block = append(block, u...) // z końcowym NUL
	}
	return append(block, 0), nil
}

// killOnCloseJob tworzy obiekt zadania, który zabija wszystkie swoje procesy, gdy ostatni uchwyt do niego zniknie (też gdy
// usługa padnie): pomocnik nigdy nie przeżyje usługi.
func killOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}
	return job, nil
}

// startWithToken tworzy proces pomocnika z podanym tokenem procesu (procTok) tak samo jak robi to usługa: pulpit winsta0\default,
// potoki jako standardowe wejście i wyjście, bez okna konsoli, a dziecko dziedziczy WYŁĄCZNIE trzy potoki
// (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), nigdy pozostałych uchwytów dziedziczalnych usługi. Proces powstaje zawieszony, wchodzi do
// obiektu zadania z KILL_ON_JOB_CLOSE i dopiero wtedy rusza; jeśli nie uda się go objąć zadaniem, jest zabijany, a start kończy
// się błędem (pomocnik nie może działać poza zadaniem). Środowisko: minimalEnv (systemowe) albo z tokenu envTok (użytkownika).
// args to argumenty wiersza poleceń (podproces consent). Ta sama ścieżka kodu w produkcji i w teście wejścia (w teście procTok i envTok to kopia tokenu bieżącego procesu, bo
// WTSQueryUserToken wymaga konta SYSTEM).
func startWithToken(procTok, envTok windows.Token, minimalEnv bool, session uint32, exe string, log *slog.Logger, args ...string) (Process, error) {
	var env *uint16
	var minimal []uint16
	if minimalEnv {
		var err error
		if minimal, err = minimalEnvBlock(); err != nil {
			return nil, fmt.Errorf("środowisko pomocnika: %w", err)
		}
		env = &minimal[0]
	} else {
		if err := windows.CreateEnvironmentBlock(&env, envTok, false); err != nil {
			return nil, fmt.Errorf("środowisko użytkownika: %w", err)
		}
		defer windows.DestroyEnvironmentBlock(env)
	}

	job, err := killOnCloseJob()
	if err != nil {
		return nil, err
	}

	// Od utworzenia potoków do końca CreateProcessAsUser nikt inny w usłudze nie tworzy procesów z dziedziczeniem uchwytów
	// (os/exec bierze ForkLock do odczytu), więc uchwyty dziecka nie wyciekną do cudzych procesów w tym oknie czasu.
	syscall.ForkLock.Lock()
	defer syscall.ForkLock.Unlock()

	inParent, inChild, err := inheritablePipe(true)
	if err != nil {
		windows.CloseHandle(job)
		return nil, err
	}
	outParent, outChild, err := inheritablePipe(false)
	if err != nil {
		windows.CloseHandle(job)
		windows.CloseHandle(inParent)
		windows.CloseHandle(inChild)
		return nil, err
	}
	errParent, errChild, err := inheritablePipe(false)
	if err != nil {
		windows.CloseHandle(job)
		for _, h := range []windows.Handle{inParent, inChild, outParent, outChild} {
			windows.CloseHandle(h)
		}
		return nil, err
	}
	closeAll := func(hs ...windows.Handle) {
		for _, h := range hs {
			windows.CloseHandle(h)
		}
	}

	// Lista uchwytów do odziedziczenia: tylko końce potoków dziecka.
	inherit := []windows.Handle{inChild, outChild, errChild}
	attrs, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		closeAll(job, inParent, inChild, outParent, outChild, errParent, errChild)
		return nil, fmt.Errorf("lista atrybutów procesu: %w", err)
	}
	defer attrs.Delete()
	if err := attrs.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&inherit[0]), uintptr(len(inherit))*unsafe.Sizeof(inherit[0])); err != nil {
		closeAll(job, inParent, inChild, outParent, outChild, errParent, errChild)
		return nil, fmt.Errorf("lista uchwytów do odziedziczenia: %w", err)
	}

	desktop, _ := windows.UTF16PtrFromString(`winsta0\default`)
	var si windows.StartupInfoEx
	si.StartupInfo = windows.StartupInfo{Desktop: desktop, Flags: windows.STARTF_USESTDHANDLES, StdInput: inChild, StdOutput: outChild, StdErr: errChild}
	si.StartupInfo.Cb = uint32(unsafe.Sizeof(si))
	si.ProcThreadAttributeList = attrs.List()
	var pi windows.ProcessInformation
	cmdArgs := []string{windows.EscapeArg(exe)}
	for _, a := range args {
		cmdArgs = append(cmdArgs, windows.EscapeArg(a))
	}
	cmdLine, _ := windows.UTF16PtrFromString(strings.Join(cmdArgs, " "))
	dir, _ := windows.UTF16PtrFromString(filepath.Dir(exe))
	const createNoWindow = 0x08000000
	err = windows.CreateProcessAsUser(procTok, nil, cmdLine, nil, nil, true,
		windows.CREATE_UNICODE_ENVIRONMENT|createNoWindow|windows.EXTENDED_STARTUPINFO_PRESENT|windows.CREATE_SUSPENDED, env, dir, &si.StartupInfo, &pi)
	runtime.KeepAlive(minimal)
	// Końce dziecka są już odziedziczone (albo niepotrzebne po błędzie).
	closeAll(inChild, outChild, errChild)
	if err != nil {
		closeAll(job, inParent, outParent, errParent)
		return nil, fmt.Errorf("CreateProcessAsUser: %w", err)
	}
	// Zawieszony proces wchodzi do zadania, zanim wykona choćby jedną instrukcję.
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		closeAll(pi.Thread, pi.Process, job, inParent, outParent, errParent)
		return nil, fmt.Errorf("AssignProcessToJobObject: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateProcess(pi.Process, 1)
		closeAll(pi.Thread, pi.Process, job, inParent, outParent, errParent)
		return nil, fmt.Errorf("ResumeThread: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	log.Info("pomocnik pulpitu uruchomiony w sesji użytkownika", "session", session, "pid", pi.ProcessId)

	stdin := os.NewFile(uintptr(inParent), "helper-stdin")
	stdout := os.NewFile(uintptr(outParent), "helper-stdout")
	stderr := os.NewFile(uintptr(errParent), "helper-stderr")
	proc := pi.Process
	var closeJobOnce sync.Once
	closeJob := func() { closeJobOnce.Do(func() { windows.CloseHandle(job) }) }
	kill := func() { _ = windows.TerminateProcess(proc, 1) }
	wait := func() {
		_, _ = windows.WaitForSingleObject(proc, windows.INFINITE)
		windows.CloseHandle(proc)
		closeJob()
		stdout.Close()
		stderr.Close()
	}
	p := newPipeProc(stdin, stdout, stderr, kill, wait, log)
	p.pid, p.closeJob = pi.ProcessId, closeJob
	return p, nil
}
