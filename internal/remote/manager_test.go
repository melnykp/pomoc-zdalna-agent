package remote

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeModule udaje klienta pulpitu i zapamiętuje ustawiane hasła.
type fakeModule struct {
	mu          sync.Mutex
	installed   bool
	id          string
	passwords   []string
	connected   bool
	connErr     error
	failSetPass error
	configured  int
}

func (f *fakeModule) Installed() bool { return f.installed }

func (f *fakeModule) ID(context.Context) (string, error) { return f.id, nil }

func (f *fakeModule) SetPassword(_ context.Context, pw string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSetPass != nil {
		return f.failSetPass
	}
	f.passwords = append(f.passwords, pw)
	return nil
}

func (f *fakeModule) EnsureConfig(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configured++
	return nil
}

func (f *fakeModule) Running(context.Context) bool { return f.installed }

func (f *fakeModule) Connected(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.connected, f.connErr
}

func (f *fakeModule) setConnected(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.connected = v
}

func (f *fakeModule) lastPassword() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.passwords) == 0 {
		return ""
	}
	return f.passwords[len(f.passwords)-1]
}

type recorder struct {
	mu     sync.Mutex
	events []string
}

func (r *recorder) emit(id, state string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, id+":"+state)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.events...)
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newManager(t *testing.T) (*Manager, *fakeModule, *recorder, *clock) {
	t.Helper()
	mod := &fakeModule{installed: true, id: "123456789"}
	rec := &recorder{}
	clk := &clock{t: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)}
	m := NewManager(Options{Module: mod, Emit: rec.emit, Now: clk.now, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	return m, mod, rec, clk
}

func TestOpenSetsOneTimePasswordAndReturnsIdentity(t *testing.T) {
	m, mod, _, clk := newManager(t)
	s, err := m.Open(context.Background(), "sess-1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if s.RemoteID != "123456789" || len(s.OTP) != OTPLength || s.ID != "sess-1" {
		t.Fatalf("sesja: %+v", s)
	}
	if mod.lastPassword() != s.OTP {
		t.Fatal("hasło sesji powinno zostać ustawione w kliencie")
	}
	if want := clk.t.Add(DefaultTTL); !s.ExpiresAt.Equal(want) {
		t.Fatalf("domyślny czas życia: %v, oczekiwano %v", s.ExpiresAt, want)
	}
	if mod.configured != 1 {
		t.Fatalf("konfiguracja powinna być sprawdzona przed sesją: %d", mod.configured)
	}
	if a, ok := m.Active(); !ok || a.OTP != "" {
		t.Fatalf("Active nie może ujawniać hasła: %+v %v", a, ok)
	}
}

func TestTTLIsClamped(t *testing.T) {
	cases := map[string]struct{ in, want time.Duration }{
		"za krótki": {time.Second, MinTTL},
		"za długi":  {time.Hour, MaxTTL},
		"normalny":  {90 * time.Second, 90 * time.Second},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			m, _, _, clk := newManager(t)
			s, err := m.Open(context.Background(), "s", c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := s.ExpiresAt.Sub(clk.t); got != c.want {
				t.Fatalf("czas życia: %v, oczekiwano %v", got, c.want)
			}
		})
	}
}

func TestSessionLifecycleLocksAccessAfterDisconnect(t *testing.T) {
	m, mod, rec, _ := newManager(t)
	s, _ := m.Open(context.Background(), "s1", 0)

	m.Tick(context.Background()) // nikt się jeszcze nie połączył
	if len(rec.list()) != 0 {
		t.Fatalf("bez połączenia nie ma zdarzeń: %v", rec.list())
	}

	mod.setConnected(true)
	m.Tick(context.Background())
	if got := rec.list(); len(got) != 1 || got[0] != "s1:connected" {
		t.Fatalf("zdarzenia po połączeniu: %v", got)
	}
	if mod.lastPassword() != s.OTP {
		t.Fatal("w trakcie połączenia hasło nie może się zmienić")
	}

	mod.setConnected(false)
	m.Tick(context.Background())
	if got := rec.list(); len(got) != 2 || got[1] != "s1:disconnected" {
		t.Fatalf("zdarzenia po rozłączeniu: %v", got)
	}
	if mod.lastPassword() == s.OTP || len(mod.lastPassword()) != 48 {
		t.Fatalf("po sesji klient powinien dostać hasło zamykające: %q", mod.lastPassword())
	}
	if _, ok := m.Active(); ok {
		t.Fatal("sesja powinna się skończyć")
	}
}

func TestPasswordExpiresWhenNobodyConnects(t *testing.T) {
	m, mod, rec, clk := newManager(t)
	s, _ := m.Open(context.Background(), "s2", 60*time.Second)

	clk.t = clk.t.Add(59 * time.Second)
	m.Tick(context.Background())
	if _, ok := m.Active(); !ok {
		t.Fatal("przed upływem czasu sesja trwa")
	}

	clk.t = clk.t.Add(2 * time.Second)
	m.Tick(context.Background())
	if got := rec.list(); len(got) != 1 || got[0] != "s2:expired" {
		t.Fatalf("zdarzenia: %v", got)
	}
	if mod.lastPassword() == s.OTP {
		t.Fatal("wygasłe hasło musi zostać zastąpione hasłem zamykającym")
	}
}

func TestConnectedSessionDoesNotExpireByTime(t *testing.T) {
	m, mod, rec, clk := newManager(t)
	_, _ = m.Open(context.Background(), "s3", MinTTL)
	mod.setConnected(true)
	m.Tick(context.Background())
	clk.t = clk.t.Add(2 * time.Hour)
	m.Tick(context.Background())
	if got := rec.list(); len(got) != 1 || got[0] != "s3:connected" {
		t.Fatalf("trwająca sesja nie wygasa z czasem: %v", got)
	}
}

func TestOnlyOneSessionAtATime(t *testing.T) {
	m, _, _, clk := newManager(t)
	if _, err := m.Open(context.Background(), "a", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Open(context.Background(), "b", 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("druga sesja powinna dostać ErrBusy: %v", err)
	}
	// Wygasła, a jeszcze nie zamknięta sesja nie blokuje nowej.
	clk.t = clk.t.Add(DefaultTTL + time.Second)
	if _, err := m.Open(context.Background(), "b", 0); err != nil {
		t.Fatalf("po wygaśnięciu nowa sesja powinna się udać: %v", err)
	}
}

func TestCloseLocksAccessAndRejectsForeignSession(t *testing.T) {
	m, mod, rec, _ := newManager(t)
	s, _ := m.Open(context.Background(), "mine", 0)
	if err := m.Close(context.Background(), "inna"); !errors.Is(err, ErrNoSession) {
		t.Fatalf("zamknięcie cudzej sesji: %v", err)
	}
	if err := m.Close(context.Background(), "mine"); err != nil {
		t.Fatal(err)
	}
	if got := rec.list(); len(got) != 1 || got[0] != "mine:closed" {
		t.Fatalf("zdarzenia: %v", got)
	}
	if mod.lastPassword() == s.OTP {
		t.Fatal("po zamknięciu hasło sesji nie może zostać")
	}
	// Zamknięcie, gdy nic nie trwa, też zamyka dostęp (na wszelki wypadek) i nie jest błędem.
	before := len(mod.passwords)
	if err := m.Close(context.Background(), ""); err != nil || len(mod.passwords) != before+1 {
		t.Fatalf("zamknięcie bez sesji: err=%v haseł %d -> %d", err, before, len(mod.passwords))
	}
}

func TestOpenFailsWhenModuleMissingOrPasswordCannotBeSet(t *testing.T) {
	m, mod, _, _ := newManager(t)
	mod.installed = false
	if _, err := m.Open(context.Background(), "x", 0); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("brak klienta: %v", err)
	}
	mod.installed = true
	mod.failSetPass = errors.New("odmowa")
	if _, err := m.Open(context.Background(), "x", 0); err == nil || strings.Contains(err.Error(), "dostęp") {
		t.Fatalf("błąd ustawienia hasła powinien zostać zgłoszony: %v", err)
	}
	if _, ok := m.Active(); ok {
		t.Fatal("nieudane otwarcie nie może zostawić sesji")
	}
}

func TestPrepareLocksAccessOnStart(t *testing.T) {
	m, mod, _, _ := newManager(t)
	if err := m.Prepare(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(mod.lastPassword()) != 48 || mod.configured != 1 {
		t.Fatalf("start powinien zamknąć dostęp i sprawdzić konfigurację: hasło %q, konfiguracji %d", mod.lastPassword(), mod.configured)
	}

	mod.installed = false
	before := len(mod.passwords)
	if err := m.Prepare(context.Background()); err != nil || len(mod.passwords) != before {
		t.Fatalf("bez klienta Prepare nic nie robi: err=%v", err)
	}
}
