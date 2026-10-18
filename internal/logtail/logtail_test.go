package logtail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

func writeLines(t *testing.T, path string, from, to int, extra ...string) {
	t.Helper()
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, `{"time":"t%d","msg":"linia %d"}`+"\n", i, i)
	}
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadReturnsLastLinesOfBothLogs(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "agent.log"), 1, 500)
	writeLines(t, filepath.Join(dir, "watchdog.log"), 1, 5)
	res := Read(Options{Dir: dir, Lines: 3})
	if len(res.Sources) != 2 || res.Sources[0].Name != "agent.log" || res.Sources[1].Name != "watchdog.log" {
		t.Fatalf("źródła: %+v", res.Sources)
	}
	a := res.Sources[0].Lines
	if len(a) != 3 || !strings.Contains(a[2], "linia 500") || !strings.Contains(a[0], "linia 498") {
		t.Fatalf("ogon agenta: %v", a)
	}
	if w := res.Sources[1].Lines; len(w) != 3 || !strings.Contains(w[2], "linia 5") {
		t.Fatalf("ogon nadzorcy: %v", w)
	}
}

func TestReadClampsLinesAndDefaults(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "agent.log"), 1, 1000)
	if got := len(Read(Options{Dir: dir, Source: wire.LogsSourceAgent, Lines: 100000}).Sources[0].Lines); got > wire.LogsTailMaxLines {
		t.Fatalf("linii %d ponad limit %d", got, wire.LogsTailMaxLines)
	}
	if got := len(Read(Options{Dir: dir, Source: wire.LogsSourceAgent}).Sources[0].Lines); got != wire.LogsTailDefaultLines {
		t.Fatalf("domyślnie %d linii, oczekiwano %d", got, wire.LogsTailDefaultLines)
	}
	if got := Read(Options{Dir: dir, Source: "dziwne"}); len(got.Sources) != 2 {
		t.Fatalf("nieznane źródło powinno dać oba dzienniki: %+v", got.Sources)
	}
}

func TestReadRedactsSensitiveLinesAndCountsThem(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "agent.log"), 1, 3,
		`{"msg":"remote.otp wysłane","otp":"Jednorazowe2026HasloSesji"}`,
		`{"msg":"ustawiono Password=abc"}`,
		`{"msg":"hasło sesji ustawione"}`,
		`{"msg":"invitation Token odrzucony"}`,
		`{"msg":"normalna linia"}`)
	res := Read(Options{Dir: dir, Source: wire.LogsSourceAgent})
	joined := strings.Join(res.Sources[0].Lines, "\n")
	for _, secret := range []string{"Jednorazowe2026HasloSesji", "abc", "Token"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("wynik zawiera %q:\n%s", secret, joined)
		}
	}
	if res.Redacted != 4 || !strings.Contains(joined, "normalna linia") {
		t.Fatalf("zastąpiono %d linii (oczekiwano 4), wynik:\n%s", res.Redacted, joined)
	}
}

func TestReadEnforcesByteLimitDroppingOldestLines(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 1; i <= 400; i++ {
		fmt.Fprintf(&b, "%04d %s\n", i, strings.Repeat("x", 300)) // 400 × ~305 B ≈ 120 KB
	}
	if err := os.WriteFile(filepath.Join(dir, "agent.log"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	res := Read(Options{Dir: dir, Source: wire.LogsSourceAgent, Lines: 400})
	s := res.Sources[0]
	if res.Bytes > wire.LogsTailMaxBytes || !s.Truncated {
		t.Fatalf("bajtów %d (limit %d), obcięto=%v", res.Bytes, wire.LogsTailMaxBytes, s.Truncated)
	}
	if !strings.HasPrefix(s.Lines[len(s.Lines)-1], "0400") {
		t.Fatalf("ostatnia linia powinna zostać: %q", s.Lines[len(s.Lines)-1])
	}
}

func TestReadFillsFromRotatedFileAndHandlesMissing(t *testing.T) {
	dir := t.TempDir()
	writeLines(t, filepath.Join(dir, "agent.log.1"), 1, 10)
	writeLines(t, filepath.Join(dir, "agent.log"), 11, 12)
	res := Read(Options{Dir: dir, Source: wire.LogsSourceBoth, Lines: 5})
	a := res.Sources[0]
	if len(a.Lines) != 5 || !strings.Contains(a.Lines[0], "linia 8") || !strings.Contains(a.Lines[4], "linia 12") {
		t.Fatalf("ogon z rotacją: %v", a.Lines)
	}
	if w := res.Sources[1]; !w.Missing || len(w.Lines) != 0 {
		t.Fatalf("brak watchdog.log: %+v", w)
	}
}

func TestReadTruncatesVeryLongLinesAndHandlesCRLF(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "agent.log"), []byte("pierwsza\r\n"+strings.Repeat("a", 5000)+"\r\nostatnia\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l := Read(Options{Dir: dir, Source: wire.LogsSourceAgent}).Sources[0].Lines
	if len(l) != 3 || l[0] != "pierwsza" || l[2] != "ostatnia" || len(l[1]) > maxLineChars+4 {
		t.Fatalf("linie: %q", l)
	}
}

func TestReadWorksWhileFileIsBeingWritten(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, "agent.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() // logger trzyma plik otwarty do zapisu przez cały czas życia agenta
	fmt.Fprintln(f, "jedna linia")
	if got := Read(Options{Dir: dir, Source: wire.LogsSourceAgent}).Sources[0]; len(got.Lines) != 1 || got.Error != "" {
		t.Fatalf("odczyt przy otwartym zapisie: %+v", got)
	}
}
