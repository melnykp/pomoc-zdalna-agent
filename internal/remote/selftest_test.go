package remote

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// selfTestModule to atrapa klienta, który „łączy się” po kilku odpytaniach i „rozłącza” po kolejnych.
type selfTestModule struct {
	fakeModule
	polls       int
	connectAt   int
	disconnect  int
	installedOK bool
	version     string
}

func (s *selfTestModule) Installed() bool { return s.installed }

func (s *selfTestModule) Install(context.Context, string) error {
	s.installed = true
	s.installedOK = true
	return nil
}

func (s *selfTestModule) Version(context.Context) string { return s.version }

func (s *selfTestModule) Connected(context.Context) (bool, error) {
	s.polls++
	return s.connectAt > 0 && s.polls >= s.connectAt && (s.disconnect == 0 || s.polls < s.disconnect), nil
}

func TestSelfTestFullFlowInstallsConfiguresOpensAndClosesAccess(t *testing.T) {
	mod := &selfTestModule{fakeModule: fakeModule{id: "424242424"}, connectAt: 2, disconnect: 5, version: "1.5.0"}
	var out bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := SelfTest(ctx, SelfTestOptions{Module: mod, Installer: "rustdesk.exe", Wait: time.Minute, Poll: 5 * time.Millisecond, Out: &out})
	if err != nil {
		t.Fatalf("samotest: %v\n%s", err, out.String())
	}
	text := out.String()
	for _, want := range []string{"klient zainstalowany", "wersja klienta: 1.5.0", "ID:    424242424", "wykryto połączenie", "rozłączenie wykryte", "wszystkie kroki przeszły"} {
		if !strings.Contains(text, want) {
			t.Errorf("w wyniku brakuje %q:\n%s", want, text)
		}
	}
	if !mod.installedOK {
		t.Error("brak klienta powinien wywołać instalację")
	}
	if len(mod.lastPassword()) != 48 {
		t.Errorf("po samoteście klient ma mieć hasło zamykające, jest: %q", mod.lastPassword())
	}
}

func TestSelfTestFailsWithoutInstallerWhenClientMissing(t *testing.T) {
	mod := &selfTestModule{fakeModule: fakeModule{id: "1"}}
	var out bytes.Buffer
	if err := SelfTest(context.Background(), SelfTestOptions{Module: mod, Out: &out}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("bez klienta i instalatora: %v", err)
	}
	if !strings.Contains(out.String(), "--installer") {
		t.Fatalf("komunikat powinien podpowiedzieć --installer:\n%s", out.String())
	}
}

func TestSelfTestReportsExpiryWhenNobodyConnects(t *testing.T) {
	mod := &selfTestModule{fakeModule: fakeModule{id: "7", installed: true}}
	var out bytes.Buffer
	// Minimalny czas życia to MinTTL (30 s), więc zegar menedżera przestawiamy testowo przez bardzo krótkie Wait:
	// SelfTest przycina je do MinTTL, a test sprawdza tylko, że przerwanie kontekstem zamyka dostęp.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := SelfTest(ctx, SelfTestOptions{Module: mod, Wait: time.Second, Poll: 10 * time.Millisecond, Out: &out})
	if err == nil {
		t.Fatalf("bez połączenia samotest nie może się udać:\n%s", out.String())
	}
	if len(mod.lastPassword()) != 48 {
		t.Fatalf("po przerwaniu dostęp ma być zamknięty hasłem zamykającym, jest %q", mod.lastPassword())
	}
}
