//go:build windows

package winput

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
)

func TestContextDescribesThisProcess(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	c := Context()
	t.Logf("kontekst tego procesu: %s", c)
	if c.PID == 0 || c.User == "" || c.IntegrityRID == 0 || c.Integrity == "unknown" {
		t.Fatalf("niepełny kontekst: %+v", c)
	}
	if c.WindowStation == "" || c.ThreadDesktop == "" {
		t.Fatalf("brak stacji okien albo pulpitu wątku: %+v", c)
	}
	switch c.ElevationType {
	case "default", "full", "limited":
	default:
		t.Fatalf("typ podniesienia %q", c.ElevationType)
	}
}

func TestIntegrityNames(t *testing.T) {
	for rid, want := range map[uint32]string{0: "unknown", 0x1000: "low", 0x2000: "medium", 0x2100: "medium", 0x3000: "high", 0x4000: "system", 0x0800: "untrusted"} {
		if got := IntegrityName(rid); got != want {
			t.Errorf("RID 0x%X → %q, oczekiwano %q", rid, got, want)
		}
	}
}

func TestForegroundComparesIntegrityWithOwn(t *testing.T) {
	f := Foreground(0xFFFF) // nasz poziom „najwyższy”: nic nie może być wyższe
	t.Logf("pierwszy plan: %+v", f)
	if f.PID != 0 && !f.Unreadable && f.Higher {
		t.Fatalf("przy najwyższym własnym poziomie okno nie może być wyższe: %+v", f)
	}
	g := Foreground(0) // nasz poziom „zerowy”: każde czytelne okno jest wyższe
	if g.PID != 0 && !g.Unreadable && g.Integrity != "" && !g.Higher {
		t.Fatalf("przy zerowym własnym poziomie okno powinno być wyższe: %+v", g)
	}
}

func TestSendInputErrorExplainsItself(t *testing.T) {
	e := &SendInputError{Op: "klawisz", Errno: syscall.ERROR_ACCESS_DENIED, ThreadDesktop: "Default", InputDesktop: "Winlogon"}
	msg := e.Error()
	for _, want := range []string{"SendInput(klawisz)", "5", "Default", "Winlogon"} {
		if !contains(msg, want) {
			t.Fatalf("komunikat %q nie zawiera %q", msg, want)
		}
	}
	var target *SendInputError
	if !errors.As(error(e), &target) || !target.IsAccessDenied() {
		t.Fatal("błąd powinien dawać się rozpoznać i klasyfikować jako odmowa dostępu")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestInjectorSetMonitorAffectsMoveCoordinates(t *testing.T) {
	// Bez wstrzykiwania: sprawdzamy tylko, że SetMonitor zmienia to, co odczytuje Move (atomowa podmiana zamiast kopiowania struktury).
	j := &Injector{}
	j.SetMonitor(-1920, 8, 1920, 1200)
	l, tp, w, h := j.monitor()
	if l != -1920 || tp != 8 || w != 1920 || h != 1200 {
		t.Fatalf("monitor: %d %d %d %d", l, tp, w, h)
	}
}
