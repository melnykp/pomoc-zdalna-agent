//go:build windows

package remote

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

// Pomocnik uruchomiony ścieżką usługi (startWithToken) siedzi w obiekcie zadania z KILL_ON_JOB_CLOSE: zamknięcie ostatniego uchwytu
// zadania (tak jak wtedy, gdy usługa padnie) zabija go, więc nie przeżyje usługi. Test sprawdza, że potomek CreateProcessAsUser z
// naszym tokenem faktycznie wchodzi do zadania i że zamknięcie zadania kończy proces.
func TestHelperRunsInKillOnCloseJob(t *testing.T) {
	exe := buildHelperForTest(t)
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	launch := ownTokenLauncher(t, false, true)
	p, err := launch(context.Background(), exe, log)
	if err != nil {
		t.Fatal(err)
	}
	pp, ok := p.(*pipeProc)
	if !ok || pp.pid == 0 || pp.closeJob == nil {
		t.Fatalf("pomocnik nie niesie danych zadania: %T %+v", p, pp)
	}
	t.Cleanup(p.Kill)

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pp.pid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	var inJob int32
	if r, _, e := procIsProcessInJob.Call(uintptr(h), 0, uintptr(unsafe.Pointer(&inJob))); r == 0 {
		t.Fatalf("IsProcessInJob: %v", e)
	}
	if inJob == 0 {
		t.Fatal("pomocnik nie jest w obiekcie zadania")
	}
	if ev, _ := windows.WaitForSingleObject(h, 0); ev != uint32(windows.WAIT_TIMEOUT) {
		t.Fatalf("pomocnik skończył się przed zamknięciem zadania (wait=%d)", ev)
	}

	// Zamknięcie uchwytu zadania (jak śmierć usługi) kończy pomocnika bez udziału usługi.
	pp.closeJob()
	ev, err := windows.WaitForSingleObject(h, 10_000)
	if err != nil || ev != windows.WAIT_OBJECT_0 {
		t.Fatalf("pomocnik przeżył zamknięcie zadania (wait=%d err=%v)", ev, err)
	}
	select {
	case _, open := <-pp.Messages():
		for open { // opróżnij ewentualne komunikaty, kanał ma się zamknąć
			_, open = <-pp.Messages()
		}
	case <-time.After(5 * time.Second):
		t.Fatal("kanał komunikatów pomocnika nie zamknął się po śmierci procesu")
	}
}

// Minimalne środowisko ma tylko zmienne systemowe, posortowane, i nie niesie niczego z profilu ani PATH użytkownika.
func TestMinimalEnvBlockHasOnlySystemVariables(t *testing.T) {
	t.Setenv("PATH", `C:\Users\ktos\evil`)
	t.Setenv("GODEBUG", "x=1")
	blk, err := minimalEnvBlock()
	if err != nil {
		t.Fatal(err)
	}
	var vars []string
	start := 0
	for i, c := range blk {
		if c == 0 {
			if i == start { // pusty napis = koniec bloku
				break
			}
			vars = append(vars, windows.UTF16ToString(blk[start:i]))
			start = i + 1
		}
	}
	if len(vars) < 5 || len(blk) < 2 || blk[len(blk)-1] != 0 || blk[len(blk)-2] != 0 {
		t.Fatalf("zły blok środowiska: %v", vars)
	}
	win, _ := windows.GetSystemWindowsDirectory()
	have := map[string]string{}
	var prev string
	for _, v := range vars {
		k, val, _ := strings.Cut(v, "=")
		have[strings.ToUpper(k)] = val
		if prev != "" && strings.ToUpper(prev) > strings.ToUpper(k) {
			t.Fatalf("zmienne nie są posortowane: %s po %s", k, prev)
		}
		prev = k
	}
	if !strings.EqualFold(have["SYSTEMROOT"], win) || !strings.EqualFold(have["WINDIR"], win) {
		t.Fatalf("SystemRoot/windir: %v", have)
	}
	if strings.Contains(strings.ToLower(have["PATH"]), "evil") || !strings.Contains(strings.ToLower(have["PATH"]), "system32") {
		t.Fatalf("PATH ma być systemowy: %q", have["PATH"])
	}
	for _, forbidden := range []string{"APPDATA", "LOCALAPPDATA", "USERPROFILE", "HOME", "GODEBUG", "USERNAME", "HOMEPATH", "ONEDRIVE"} {
		if _, ok := have[forbidden]; ok {
			t.Fatalf("minimalne środowisko nie powinno mieć %s", forbidden)
		}
	}
	if !strings.HasPrefix(strings.ToLower(have["TEMP"]), strings.ToLower(win)) || have["TEMP"] != have["TMP"] {
		t.Fatalf("TEMP/TMP mają wskazywać systemowy katalog tymczasowy: %q %q", have["TEMP"], have["TMP"])
	}
}
