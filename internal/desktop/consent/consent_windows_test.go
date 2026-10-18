//go:build windows

package consent

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/internal/ipc"
)

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func decision(t *testing.T, out *bytes.Buffer) string {
	t.Helper()
	var m ipc.DesktopMsg
	if err := ipc.ReadLine(bufio.NewReader(bytes.NewReader(out.Bytes())), &m); err != nil {
		t.Fatalf("odczyt decyzji: %v (%q)", err, out.String())
	}
	if m.Kind != ipc.DesktopConsent {
		t.Fatalf("rodzaj komunikatu: %q", m.Kind)
	}
	return m.State
}

// Podproces okna zgody przekazuje tytuł i treść dokładnie tak, jak je dostał (base64), a decyzją jest wyłącznie odpowiedź użytkownika.
func TestRunWithPassesTextAndReportsOnlyTheUsersAnswer(t *testing.T) {
	var gotTitle, gotText string
	var out bytes.Buffer
	err := RunWith(&out, b64("Tytuł"), b64("Inżynier „Jan” prosi\nTak = zezwalam"), func(title, text string) (bool, error) {
		gotTitle, gotText = title, text
		return true, nil
	})
	if err != nil || decision(t, &out) != ipc.ConsentAllow || gotTitle != "Tytuł" || gotText != "Inżynier „Jan” prosi\nTak = zezwalam" {
		t.Fatalf("err=%v tytuł=%q treść=%q wyjście=%q", err, gotTitle, gotText, out.String())
	}

	out.Reset()
	if err := RunWith(&out, b64("t"), b64("x"), func(string, string) (bool, error) { return false, nil }); err != nil || decision(t, &out) != ipc.ConsentDeny {
		t.Fatalf("odmowa: err=%v wyjście=%q", err, out.String())
	}
}

// Każdy błąd (zła treść, okno, które się nie pokazało) to odmowa, nigdy zgoda.
func TestRunWithTreatsEveryFailureAsDenial(t *testing.T) {
	var out bytes.Buffer
	called := false
	err := RunWith(&out, "%%%", b64("x"), func(string, string) (bool, error) { called = true; return true, nil })
	if err == nil || called || decision(t, &out) != ipc.ConsentDeny {
		t.Fatalf("zły base64: err=%v pokazano=%v wyjście=%q", err, called, out.String())
	}
	out.Reset()
	err = RunWith(&out, b64("t"), b64("x"), func(string, string) (bool, error) { return true, errors.New("MessageBox: błąd") })
	if err == nil || decision(t, &out) != ipc.ConsentDeny {
		t.Fatalf("błąd okna: err=%v wyjście=%q", err, out.String())
	}
}
