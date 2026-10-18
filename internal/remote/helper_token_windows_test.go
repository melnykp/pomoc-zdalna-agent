//go:build windows

package remote

import (
	"errors"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
	"github.com/melnykp/pomoc-zdalna-agent/internal/wintoken"
)

const (
	testUser    = "S-1-5-21-1-2-3-1001"
	testSession = 7
	userTok     = windows.Token(1)
)

// fakeTokens udaje operacje na tokenach razem z ich skutkami (sesja, integralność, grupa Administratorzy), żeby dało się
// sprawdzić wynik tak, jak robi to produkcja. Uchwyty to liczby, a mapa toks pilnuje, czy każdy utworzony token zostanie zamknięty
// (poza zwróconym wołającemu i poza tokenem użytkownika, który należy do wołającego).
type fakeTokens struct {
	next  windows.Token
	toks  map[windows.Token]*wintoken.Info
	calls []string

	user    wintoken.Info // cechy tokenu użytkownika
	linked  wintoken.Info // cechy tokenu połączonego
	et      uint32
	etErr   error
	userErr error // błąd odczytu cech tokenu użytkownika

	linkE, primE, sessE, intE error
	restFail                  int // tyle pierwszych wywołań restrict kończy się błędem; -1 = wszystkie
	restLua                   []bool
	intCalls                  []uint32
	sessCalls                 []uint32
	tamper                    func(op string, info *wintoken.Info) // psuje wynik operacji (test weryfikacji)
}

// userInfo zwraca typowe cechy tokenu użytkownika: filtrowany (średnia integralność, Administratorzy tylko do odmowy).
func filteredInfo() wintoken.Info {
	return wintoken.Info{UserSID: testUser, Session: testSession, IntegrityRID: wintoken.RIDMedium}
}

func newFake(et uint32) *fakeTokens {
	f := &fakeTokens{next: 100, toks: map[windows.Token]*wintoken.Info{}, et: et, user: filteredInfo()}
	f.linked = wintoken.Info{UserSID: testUser, Session: 0, IntegrityRID: wintoken.RIDHigh, AdminEnabled: true, Elevated: true}
	switch et {
	case elevationFull:
		f.user = wintoken.Info{UserSID: testUser, Session: testSession, IntegrityRID: wintoken.RIDHigh, AdminEnabled: true, Elevated: true}
	case elevationDefault:
		// konto standardowe: filtrowane nie jest, ale nie ma też Administratorów
	}
	return f
}

func (f *fakeTokens) mk(info wintoken.Info) windows.Token {
	f.next++
	cp := info
	f.toks[f.next] = &cp
	return f.next
}

func (f *fakeTokens) infoOf(t windows.Token) *wintoken.Info {
	if t == userTok {
		return &f.user
	}
	return f.toks[t]
}

func (f *fakeTokens) ops() tokenOps {
	return tokenOps{
		elevationType: func(windows.Token) (uint32, error) { f.calls = append(f.calls, "elevationType"); return f.et, f.etErr },
		linkedToken: func(windows.Token) (windows.Token, error) {
			f.calls = append(f.calls, "linked")
			if f.linkE != nil {
				return 0, f.linkE
			}
			return f.mk(f.linked), nil
		},
		toPrimary: func(t windows.Token) (windows.Token, error) {
			f.calls = append(f.calls, "toPrimary")
			if f.primE != nil {
				return 0, f.primE
			}
			return f.mk(*f.infoOf(t)), nil
		},
		setSession: func(t windows.Token, s uint32) error {
			f.calls = append(f.calls, "setSession")
			f.sessCalls = append(f.sessCalls, s)
			if f.sessE != nil {
				return f.sessE
			}
			f.toks[t].Session = s
			return nil
		},
		restrict: func(t windows.Token, lua bool) (windows.Token, error) {
			f.calls = append(f.calls, "restrict")
			f.restLua = append(f.restLua, lua)
			if f.restFail != 0 {
				if f.restFail > 0 {
					f.restFail--
				}
				return 0, errors.New("CreateRestrictedToken: odmowa")
			}
			info := *f.infoOf(t)
			if lua {
				info.AdminEnabled, info.Elevated = false, false
			}
			r := f.mk(info)
			if f.tamper != nil {
				f.tamper("restrict", f.toks[r])
			}
			return r, nil
		},
		setIntegrity: func(t windows.Token, rid uint32) error {
			f.calls = append(f.calls, "setIntegrity")
			f.intCalls = append(f.intCalls, rid)
			if f.intE != nil && rid > wintoken.RIDMedium {
				return f.intE // obniżenie zawsze działa, podniesienie wymaga SeTcb
			}
			f.toks[t].IntegrityRID = rid
			if f.tamper != nil {
				f.tamper("setIntegrity", f.toks[t])
			}
			return nil
		},
		inspect: func(t windows.Token) (wintoken.Info, error) {
			if t == userTok && f.userErr != nil {
				return wintoken.Info{}, f.userErr
			}
			return *f.infoOf(t), nil
		},
		closeToken: func(t windows.Token) { delete(f.toks, t) },
	}
}

func (f *fakeTokens) assertOnlyOpen(t *testing.T, keep ...windows.Token) {
	t.Helper()
	want := map[windows.Token]bool{}
	for _, k := range keep {
		want[k] = true
	}
	for tok := range f.toks {
		if !want[tok] {
			t.Fatalf("wyciek tokenu %d: nie został zamknięty; wywołania: %v", tok, f.calls)
		}
	}
}

func (f *fakeTokens) has(call string) bool {
	for _, c := range f.calls {
		if c == call {
			return true
		}
	}
	return false
}

// ---- poziom „integrity” (domyślny) ----

func TestIntegrityLevelRaisesFilteredTokenWithoutAdministratorsGroup(t *testing.T) {
	for _, et := range []uint32{elevationLimited, elevationDefault} {
		f := newFake(et)
		tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperIntegrity, f.ops())
		if err != nil {
			t.Fatal(err)
		}
		if c.Kind != TokenIntegrity || c.Fallback || c.Lowered || c.Integrity != "high" || c.AdminGroup {
			t.Fatalf("typ podniesienia %d, wybór: %+v", et, c)
		}
		got := f.toks[tok]
		if tok == userTok || got == nil || got.IntegrityRID != wintoken.RIDHigh || got.AdminEnabled || got.UserSID != testUser || got.Session != testSession {
			t.Fatalf("token pomocnika: %+v", got)
		}
		// Zwykły token użytkownika, nigdy połączony token administratora; uprawnienia odjęte bez LUA (token już filtrowany).
		if f.has("linked") {
			t.Fatalf("poziom integrity nie sięga po token administratora: %v", f.calls)
		}
		if len(f.restLua) != 1 || f.restLua[0] {
			t.Fatalf("restrict powinien zdjąć uprawnienia bez LUA_TOKEN: %v", f.restLua)
		}
		if len(f.intCalls) != 1 || f.intCalls[0] != wintoken.RIDHigh {
			t.Fatalf("integralność: %v", f.intCalls)
		}
		f.assertOnlyOpen(t, tok) // pośrednia kopia zamknięta, zostaje wynik
		done()
		f.assertOnlyOpen(t)
	}
}

func TestIntegrityLevelOnElevatedTokenAddsLUAAndNeverKeepsAdministrators(t *testing.T) {
	f := newFake(elevationFull) // UAC wyłączone / wbudowany administrator
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperIntegrity, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	got := f.toks[tok]
	if c.Kind != TokenIntegrity || got == nil || got.AdminEnabled || got.IntegrityRID != wintoken.RIDHigh {
		t.Fatalf("wybór %+v, token %+v", c, got)
	}
	if len(f.restLua) != 1 || !f.restLua[0] {
		t.Fatalf("podniesiony token musi dostać LUA_TOKEN (Administratorzy tylko do odmowy): %v", f.restLua)
	}
	done()
	f.assertOnlyOpen(t)
}

// Pusty poziom to „user”: żadna aktualizacja nie podnosi uprawnień pomocnika po cichu (ani nie rusza niepodniesionego tokenu).
func TestEmptyLevelMeansUserNeverRaisesIntegrity(t *testing.T) {
	f := newFake(elevationLimited)
	tok, c, done, err := chooseHelperToken(userTok, testSession, "", f.ops())
	if err != nil || tok != userTok || c.Kind != TokenUserRequested || c.Level != config.DesktopHelperUser || c.Integrity != "medium" {
		t.Fatalf("tok=%d %+v err=%v", tok, c, err)
	}
	if f.has("setIntegrity") || f.has("linked") {
		t.Fatalf("poziom domyślny nie podnosi uprawnień: %v", f.calls)
	}
	done()
}

func TestIntegrityFailureFallsBackToMediumTokenWithReason(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(f *fakeTokens)
		reason string
	}{
		{"brak SeTcb przy podnoszeniu integralności", func(f *fakeTokens) { f.intE = errors.New("1314") }, "SeTcbPrivilege"},
		{"odjęcie uprawnień", func(f *fakeTokens) { f.restFail = 1 }, "odjęcie uprawnień"},
		{"poziom identyfikacji", func(f *fakeTokens) { f.primE = windows.ERROR_BAD_IMPERSONATION_LEVEL }, "SeTcbPrivilege"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(elevationLimited)
			c.setup(f)
			tok, ch, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperIntegrity, f.ops())
			// Token niepodniesiony: zapas to token użytkownika bez zmian (jak w 0.4.2).
			if err != nil || tok != userTok || ch.Kind != TokenUserFallback || !ch.Fallback || ch.Lowered || ch.Integrity != "medium" {
				t.Fatalf("tok=%d %+v err=%v", tok, ch, err)
			}
			if !strings.Contains(ch.Reason, c.reason) {
				t.Fatalf("powód %q nie zawiera %q", ch.Reason, c.reason)
			}
			f.assertOnlyOpen(t)
			done()
			f.assertOnlyOpen(t)
		})
	}
}

// ---- zapas i poziom „user” przy podniesionym tokenie (UAC wyłączone) ----

func TestFullTokenFallbackAndUserLevelAreLoweredNeverFull(t *testing.T) {
	// Poziom „integrity” zawodzi (brak SeTcb), a token użytkownika jest pełny: zapas to jego odchudzona wersja.
	f := newFake(elevationFull)
	f.intE = errors.New("1314")
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperIntegrity, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	got := f.toks[tok]
	if tok == userTok || got == nil || c.Kind != TokenUserFallback || !c.Lowered || got.AdminEnabled || got.IntegrityRID != wintoken.RIDMedium {
		t.Fatalf("zapas dla pełnego tokenu: tok=%d %+v token=%+v", tok, c, got)
	}
	f.assertOnlyOpen(t, tok)
	done()
	f.assertOnlyOpen(t)

	// Poziom „user” z pełnym tokenem: odchudzony i średni, z LUA_TOKEN i obniżoną integralnością.
	g := newFake(elevationFull)
	tok, c, done, err = chooseHelperToken(userTok, testSession, config.DesktopHelperUser, g.ops())
	if err != nil {
		t.Fatal(err)
	}
	got = g.toks[tok]
	if tok == userTok || c.Kind != TokenUserRequested || !c.Lowered || got.AdminEnabled || got.IntegrityRID != wintoken.RIDMedium {
		t.Fatalf("poziom user z pełnym tokenem: tok=%d %+v token=%+v", tok, c, got)
	}
	if len(g.restLua) != 1 || !g.restLua[0] || len(g.intCalls) != 1 || g.intCalls[0] != wintoken.RIDMedium {
		t.Fatalf("oczekiwano LUA_TOKEN i obniżenia do średniej: lua=%v integralność=%v", g.restLua, g.intCalls)
	}
	done()
	g.assertOnlyOpen(t)
}

func TestFullTokenWhenLoweringImpossibleRefusesInsteadOfReturningFullToken(t *testing.T) {
	for _, level := range []string{config.DesktopHelperUser, config.DesktopHelperIntegrity, config.DesktopHelperAdmin} {
		t.Run(level, func(t *testing.T) {
			f := newFake(elevationFull)
			f.restFail = -1 // CreateRestrictedToken zawsze odmawia
			tok, _, done, err := chooseHelperToken(userTok, testSession, level, f.ops())
			if err == nil || tok != 0 {
				t.Fatalf("oczekiwano odmowy startu, a jest tok=%d err=%v", tok, err)
			}
			if tok == userTok {
				t.Fatal("pełny token użytkownika nie może trafić do pomocnika")
			}
			f.assertOnlyOpen(t)
			done()
		})
	}
	// Obniżenie integralności też musi zadziałać: tu system je przyjmuje, ale wynik nadal ma wysoką integralność.
	f := newFake(elevationFull)
	f.tamper = func(op string, info *wintoken.Info) {
		if op == "setIntegrity" {
			info.IntegrityRID = wintoken.RIDHigh
		}
	}
	tok, _, _, err := chooseHelperToken(userTok, testSession, config.DesktopHelperUser, f.ops())
	if err == nil || tok != 0 {
		t.Fatalf("token o wysokiej integralności nie przechodzi weryfikacji średniej: tok=%d err=%v", tok, err)
	}
	f.assertOnlyOpen(t)
}

func TestFullTokenAdminRestrictFailureFallsBackToLoweredTokenNotUserToken(t *testing.T) {
	f := newFake(elevationFull)
	f.restFail = 1 // odmawia tylko pierwsze odjęcie uprawnień (poziom admin), zapas ma się udać
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	got := f.toks[tok]
	if tok == userTok || got == nil || c.Kind != TokenUserFallback || !c.Lowered || got.AdminEnabled {
		t.Fatalf("zapas po nieudanym odjęciu uprawnień pełnego tokenu: tok=%d %+v token=%+v", tok, c, got)
	}
	done()
	f.assertOnlyOpen(t)
}

func TestUserLevelKeepsFilteredTokenAsIs(t *testing.T) {
	f := newFake(elevationLimited)
	tok, c, _, err := chooseHelperToken(userTok, testSession, config.DesktopHelperUser, f.ops())
	if err != nil || tok != userTok || c.Kind != TokenUserRequested || c.Fallback || c.Lowered {
		t.Fatalf("poziom user: tok=%d %+v err=%v", tok, c, err)
	}
	for _, call := range f.calls {
		if call == "linked" || call == "restrict" || call == "toPrimary" || call == "setIntegrity" {
			t.Fatalf("poziom user nie rusza niepodniesionego tokenu: %v", f.calls)
		}
	}
}

// ---- poziom „admin” ----

func TestAdminLevelLimitedUsesLinkedTokenInUsersSession(t *testing.T) {
	f := newFake(elevationLimited)
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
	if err != nil {
		t.Fatal(err)
	}
	got := f.toks[tok]
	if c.Kind != TokenAdminLinked || c.Fallback || c.Elevation != "limited" || !c.AdminGroup || got == nil || got.Session != testSession {
		t.Fatalf("wybór %+v, token %+v", c, got)
	}
	// Połączony token ma sesję 0: musi dostać sesję użytkownika.
	if len(f.sessCalls) != 1 || f.sessCalls[0] != testSession {
		t.Fatalf("sesja tokenu administratora: %v", f.sessCalls)
	}
	want := []string{"elevationType", "linked", "toPrimary", "setSession", "restrict"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("kolejność operacji: %v, oczekiwano %v", f.calls, want)
	}
	f.assertOnlyOpen(t, tok)
	done()
	f.assertOnlyOpen(t)
}

func TestAdminLevelFullTokenIsRestrictedCopy(t *testing.T) {
	f := newFake(elevationFull)
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
	if err != nil || c.Kind != TokenAdminFull || c.Fallback || !c.AdminGroup {
		t.Fatalf("%+v err=%v", c, err)
	}
	if f.has("linked") || f.toks[tok] == nil || len(f.restLua) != 1 || f.restLua[0] {
		t.Fatalf("pełny token: kopia z odjętymi uprawnieniami bez LUA (admin ma zostać): %v %v", f.calls, f.restLua)
	}
	done()
	f.assertOnlyOpen(t)
}

func TestAdminLevelStandardAccountKeepsUserTokenAndSaysSo(t *testing.T) {
	f := newFake(elevationDefault)
	tok, c, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
	if err != nil || tok != userTok || c.Kind != TokenUserStandard || !c.Fallback {
		t.Fatalf("konto standardowe: tok=%d %+v err=%v", tok, c, err)
	}
	if !strings.Contains(c.Reason, "konto standardowe") {
		t.Fatalf("powód ma mówić wprost: %q", c.Reason)
	}
	done()
	f.assertOnlyOpen(t)
}

func TestAdminLevelFailuresFallBackToUserTokenWithExplicitReason(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(f *fakeTokens)
		reason string
	}{
		{"brak połączonego tokenu", func(f *fakeTokens) { f.linkE = errors.New("brak połączonego") }, "TokenLinkedToken"},
		{"błąd odczytu typu podniesienia", func(f *fakeTokens) { f.etErr = errors.New("odmowa") }, "typu podniesienia"},
		{"poziom identyfikacji (brak SeTcb)", func(f *fakeTokens) { f.primE = windows.ERROR_BAD_IMPERSONATION_LEVEL }, "SeTcbPrivilege"},
		{"nieudane ustawienie sesji", func(f *fakeTokens) { f.sessE = errors.New("1314") }, "sesji"},
		{"nieudane odjęcie uprawnień", func(f *fakeTokens) { f.restFail = 1 }, "odjęcie uprawnień"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(elevationLimited)
			c.setup(f)
			tok, ch, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
			if err != nil || tok != userTok || ch.Kind != TokenUserFallback || !ch.Fallback {
				t.Fatalf("oczekiwano zapasu z tokenem użytkownika: tok=%d %+v err=%v", tok, ch, err)
			}
			if !strings.Contains(ch.Reason, c.reason) {
				t.Fatalf("powód %q nie zawiera %q", ch.Reason, c.reason)
			}
			f.assertOnlyOpen(t)
			done()
			f.assertOnlyOpen(t)
		})
	}
}

// ---- sesja, użytkownik i weryfikacja wyniku ----

func TestSessionZeroIsRejected(t *testing.T) {
	for _, level := range []string{"", config.DesktopHelperIntegrity, config.DesktopHelperAdmin, config.DesktopHelperUser} {
		f := newFake(elevationLimited)
		tok, _, _, err := chooseHelperToken(userTok, 0, level, f.ops())
		if err == nil || tok != 0 || !strings.Contains(err.Error(), "sesja 0") {
			t.Fatalf("poziom %q: tok=%d err=%v", level, tok, err)
		}
		if len(f.calls) != 0 {
			t.Fatalf("po odrzuceniu sesji 0 nie wolno nic robić z tokenami: %v", f.calls)
		}
	}
}

func TestUnreadableUserTokenRefusesStart(t *testing.T) {
	f := newFake(elevationLimited)
	f.userErr = errors.New("odmowa dostępu")
	tok, _, _, err := chooseHelperToken(userTok, testSession, config.DesktopHelperUser, f.ops())
	if err == nil || tok != 0 {
		t.Fatalf("bez odczytu cech tokenu nie wiadomo, czy jest podniesiony: tok=%d err=%v", tok, err)
	}
}

func TestElevationIsRecognisedFromGroupAndIntegrityNotOnlyFromType(t *testing.T) {
	// Typ podniesienia mówi „limited”, ale token ma włączoną grupę Administratorzy: traktujemy jak podniesiony.
	f := newFake(elevationLimited)
	f.user = wintoken.Info{UserSID: testUser, Session: testSession, IntegrityRID: wintoken.RIDMedium, AdminEnabled: true}
	tok, c, _, err := chooseHelperToken(userTok, testSession, config.DesktopHelperUser, f.ops())
	if err != nil || tok == userTok || !c.Lowered {
		t.Fatalf("token z włączoną grupą Administratorzy musi zostać odchudzony: tok=%d %+v err=%v", tok, c, err)
	}
	// To samo dla wysokiej integralności bez grupy.
	g := newFake(elevationDefault)
	g.user = wintoken.Info{UserSID: testUser, Session: testSession, IntegrityRID: wintoken.RIDHigh}
	tok, c, _, err = chooseHelperToken(userTok, testSession, config.DesktopHelperUser, g.ops())
	if err != nil || tok == userTok || !c.Lowered {
		t.Fatalf("token o wysokiej integralności musi zostać obniżony: tok=%d %+v err=%v", tok, c, err)
	}
}

func TestResultMismatchIsNeverReturned(t *testing.T) {
	cases := []struct {
		name   string
		tamper func(info *wintoken.Info)
		reason string
	}{
		{"inny użytkownik", func(i *wintoken.Info) { i.UserSID = "S-1-5-18" }, "TokenUser"},
		{"inna sesja", func(i *wintoken.Info) { i.Session = 0 }, "TokenSessionId"},
		{"grupa Administratorzy włączona w poziomie integrity", func(i *wintoken.Info) { i.AdminEnabled = true }, "Administratorzy"},
		{"integralność inna niż wysoka", func(i *wintoken.Info) { i.IntegrityRID = wintoken.RIDSystem }, "integralność"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFake(elevationLimited)
			f.tamper = func(op string, info *wintoken.Info) {
				if op == "setIntegrity" {
					c.tamper(info)
				}
			}
			tok, ch, done, err := chooseHelperToken(userTok, testSession, config.DesktopHelperIntegrity, f.ops())
			// Wynik niezgodny z użytkownikiem nie przechodzi weryfikacji: zostaje zapas (token użytkownika), a niezgodny token zamknięty.
			if err != nil || tok != userTok || ch.Kind != TokenUserFallback || !strings.Contains(ch.Reason, c.reason) {
				t.Fatalf("tok=%d %+v err=%v", tok, ch, err)
			}
			f.assertOnlyOpen(t)
			done()
		})
	}
	// Poziom admin też porównuje użytkownika i sesję wyniku.
	f := newFake(elevationLimited)
	f.tamper = func(op string, info *wintoken.Info) {
		if op == "restrict" {
			info.UserSID = "S-1-5-18"
		}
	}
	tok, ch, _, err := chooseHelperToken(userTok, testSession, config.DesktopHelperAdmin, f.ops())
	if err != nil || tok != userTok || ch.Kind != TokenUserFallback || !strings.Contains(ch.Reason, "TokenUser") {
		t.Fatalf("admin z obcym użytkownikiem: tok=%d %+v err=%v", tok, ch, err)
	}
	f.assertOnlyOpen(t)
}

// ---- prawdziwe operacje na tokenach (bez SYSTEM) ----

func ownDuplicate(t *testing.T) windows.Token {
	t.Helper()
	var self windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY, &self); err != nil {
		t.Fatal(err)
	}
	defer self.Close()
	dup, err := wintoken.ToPrimary(self)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dup.Close() })
	return dup
}

var procLookupPrivName = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

// tokenPrivileges zwraca nazwy uprawnień tokenu (włączonych i wyłączonych).
func tokenPrivileges(t *testing.T, tok windows.Token) []string {
	t.Helper()
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n); err != nil {
		t.Fatal(err)
	}
	tp := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	var names []string
	for _, p := range tp.AllPrivileges() {
		var nb [128]uint16
		l := uint32(len(nb))
		if r, _, _ := procLookupPrivName.Call(0, uintptr(unsafe.Pointer(&p.Luid)), uintptr(unsafe.Pointer(&nb[0])), uintptr(unsafe.Pointer(&l))); r != 0 {
			names = append(names, windows.UTF16ToString(nb[:l]))
		}
	}
	return names
}

func TestRestrictKeepsUserSessionIntegrityAndDropsPrivileges(t *testing.T) {
	dup := ownDuplicate(t)
	before, err := wintoken.Inspect(dup)
	if err != nil {
		t.Fatal(err)
	}
	for _, lua := range []bool{false, true} {
		restricted, err := wintoken.Restrict(dup, lua)
		if err != nil {
			t.Fatalf("lua=%v: %v", lua, err)
		}
		after, err := wintoken.Inspect(restricted)
		if err != nil {
			restricted.Close()
			t.Fatal(err)
		}
		privs := tokenPrivileges(t, restricted)
		priBefore := tokenPrivileges(t, dup)
		restricted.Close()
		t.Logf("lua=%v: uprawnienia przed: %v, po: %v", lua, priBefore, privs)
		if len(privs) != 1 || privs[0] != "SeChangeNotifyPrivilege" {
			t.Fatalf("po odjęciu powinno zostać tylko SeChangeNotifyPrivilege: %v", privs)
		}
		// Ten sam użytkownik, ta sama sesja i integralność; nie jest tokenem z SID-ami ograniczającymi.
		if after.UserSID != before.UserSID || after.Session != before.Session || after.IntegrityRID != before.IntegrityRID || after.Restricted {
			t.Fatalf("lua=%v: przed %+v, po %+v", lua, before, after)
		}
		// Odjęcie uprawnień (także z LUA) nie dodaje grupy Administratorzy.
		if after.AdminEnabled && !before.AdminEnabled {
			t.Fatalf("lua=%v: grupa Administratorzy została włączona", lua)
		}
		if lua && after.AdminEnabled {
			t.Fatal("LUA_TOKEN ma zostawić grupę Administratorzy tylko do odmowy")
		}
	}
}

func TestSetIntegrityLowersButCannotRaiseWithoutSeTcb(t *testing.T) {
	dup := ownDuplicate(t)
	info, err := wintoken.Inspect(dup)
	if err != nil {
		t.Fatal(err)
	}
	if info.IntegrityRID != wintoken.RIDMedium {
		t.Skipf("test zakłada token średniej integralności, jest 0x%X", info.IntegrityRID)
	}
	// Podniesienie ponad obecny poziom bez SeTcbPrivilege nie może się udać (dlatego produkcja wymaga usługi SYSTEM).
	if runningAsSystem() {
		t.Skip("działa jako SYSTEM: podniesienie by się udało")
	}
	if err := wintoken.SetIntegrity(dup, wintoken.RIDHigh); err == nil {
		t.Fatal("podniesienie integralności bez SeTcbPrivilege nie powinno się udać")
	} else {
		t.Logf("podniesienie bez SeTcb: %v", err)
	}
	// Obniżenie działa zawsze: tak odchudzamy podniesiony token do średniej integralności.
	low, err := wintoken.ToPrimary(dup)
	if err != nil {
		t.Fatal(err)
	}
	defer low.Close()
	if err := wintoken.SetIntegrity(low, wintoken.RIDLow); err != nil {
		t.Fatal(err)
	}
	if got, _ := wintoken.Inspect(low); got.IntegrityRID != wintoken.RIDLow {
		t.Fatalf("integralność po obniżeniu: 0x%X", got.IntegrityRID)
	}
}

func TestRealOpsFallBackWithReasonWithoutSystem(t *testing.T) {
	if runningAsSystem() {
		t.Skip("test sprawdza ścieżkę bez SeTcbPrivilege; działa jako SYSTEM")
	}
	ops := realTokenOps()
	dup := ownDuplicate(t)
	info, err := wintoken.Inspect(dup)
	if err != nil {
		t.Fatal(err)
	}
	if info.AdminEnabled || info.IntegrityRID != wintoken.RIDMedium {
		t.Skipf("test zakłada zwykły token filtrowany (integralność 0x%X, administratorzy włączeni: %v)", info.IntegrityRID, info.AdminEnabled)
	}
	var session uint32
	_ = windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &session)
	if session == 0 {
		t.Skip("sesja 0")
	}

	// Poziom domyślny bez SYSTEM: podniesienie integralności nie wychodzi, więc zapas = token użytkownika z powodem.
	tok, c, done, err := chooseHelperToken(dup, session, config.DesktopHelperIntegrity, ops)
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	t.Logf("wybór bez SYSTEM: %s", c)
	if tok != dup || c.Kind != TokenUserFallback || !c.Fallback || !strings.Contains(c.Reason, "SeTcbPrivilege") {
		t.Fatalf("bez SYSTEM oczekiwano zapasu z powodem SeTcbPrivilege: tok=%d %+v", tok, c)
	}

	// Poziom „user” na zwykłym koncie: token bez zmian.
	tok2, c2, done2, err := chooseHelperToken(dup, session, config.DesktopHelperUser, ops)
	if err != nil || tok2 != dup || c2.Kind != TokenUserRequested {
		t.Fatalf("poziom user: tok=%d %+v err=%v", tok2, c2, err)
	}
	done2()

	// Poziom „admin”: z połączonym tokenem bez SeTcb DuplicateTokenEx daje ERROR_BAD_IMPERSONATION_LEVEL (token na poziomie identyfikacji).
	if et, err := ops.elevationType(dup); err == nil && et == elevationLimited {
		tok3, c3, done3, err := chooseHelperToken(dup, session, config.DesktopHelperAdmin, ops)
		if err != nil || tok3 != dup || c3.Kind != TokenUserFallback || !strings.Contains(c3.Reason, "SeTcbPrivilege") {
			t.Fatalf("admin bez SYSTEM: tok=%d %+v err=%v", tok3, c3, err)
		}
		done3()
	}
}
