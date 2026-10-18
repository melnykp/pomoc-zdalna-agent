// Package logtail czyta końcówki dzienników agenta do diagnozy z panelu (polecenie logs.tail): ostatnie N linii z agent.log
// i watchdog.log (z plikami rotacji), z limitem bajtów i zastąpieniem linii z wrażliwymi słowami (otp, password, token…)
// znacznikiem. Logi agenta nie powinny zawierać sekretów, ale wynik trafia do bazy serwera i do przeglądarki, więc filtr jest
// drugą linią obrony.
package logtail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// maxFileRead to ile bajtów od końca pliku czytamy (plik rotuje po 5 MB; ogon 200–400 linii mieści się z zapasem).
const maxFileRead = 2 << 20

// maxLineChars ucina pojedynczą linię (np. ogromny wpis JSON), żeby jedna linia nie zjadła całego limitu.
const maxLineChars = 2000

// RedactedMarker zastępuje linię z wrażliwym słowem kluczowym.
const RedactedMarker = "[usunięto linię: zawierała wrażliwe słowo kluczowe]"

var sensitiveRe = regexp.MustCompile(`(?i)otp|passw|hasł|hasl|secret|credential|token|authorization|bearer|private[_ -]?key`)

// Redact zwraca linię albo znacznik, gdy zawiera wrażliwe słowo; drugi wynik mówi, czy ją zastąpiono.
func Redact(line string) (string, bool) {
	if sensitiveRe.MatchString(line) {
		return RedactedMarker, true
	}
	return line, false
}

// Options opisuje zapytanie.
type Options struct {
	Dir      string // katalog dzienników (DataDir\logs)
	Lines    int    // ile linii z każdego pliku (przycinane do wire.LogsTailMaxLines)
	Source   string // wire.LogsSource*
	MaxBytes int    // łączny limit tekstu; 0 = wire.LogsTailMaxBytes
}

// Normalize uzupełnia domyślne i przycina wartości do limitów.
func (o Options) Normalize() Options {
	if o.Lines <= 0 {
		o.Lines = wire.LogsTailDefaultLines
	}
	if o.Lines > wire.LogsTailMaxLines {
		o.Lines = wire.LogsTailMaxLines
	}
	switch o.Source {
	case wire.LogsSourceAgent, wire.LogsSourceWatchdog, wire.LogsSourceBoth:
	default:
		o.Source = wire.LogsSourceBoth
	}
	if o.MaxBytes <= 0 || o.MaxBytes > wire.LogsTailMaxBytes {
		o.MaxBytes = wire.LogsTailMaxBytes
	}
	return o
}

// Read zwraca ogony wybranych dzienników. Brak pliku to nie błąd (Missing), bo np. nadzorca mógł jeszcze nie pisać.
func Read(o Options) wire.LogsTailResult {
	o = o.Normalize()
	var names []string
	switch o.Source {
	case wire.LogsSourceAgent:
		names = []string{"agent.log"}
	case wire.LogsSourceWatchdog:
		names = []string{"watchdog.log"}
	default:
		names = []string{"agent.log", "watchdog.log"}
	}
	res := wire.LogsTailResult{Sources: make([]wire.LogsTailSource, 0, len(names))}
	budget := o.MaxBytes / len(names)
	for _, name := range names {
		src := readOne(filepath.Join(o.Dir, name), name, o.Lines, budget, &res.Redacted)
		for _, l := range src.Lines {
			res.Bytes += len(l) + 1
		}
		res.Sources = append(res.Sources, src)
	}
	return res
}

func readOne(path, name string, want, budget int, redacted *int) wire.LogsTailSource {
	src := wire.LogsTailSource{Name: name, Lines: []string{}}
	var lines []string
	found := false
	// Pliki rotacji (name.1, name.2…) dopełniają ogon, gdy bieżący plik ma mało linii (świeżo po rotacji).
	for i := 0; i <= 5 && len(lines) < want; i++ {
		p := path
		if i > 0 {
			p = fmt.Sprintf("%s.%d", path, i)
		}
		chunk, err := tailLines(p, want-len(lines))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if i == 0 {
					continue
				}
				break
			}
			src.Error = err.Error()
			break
		}
		found = true
		lines = append(chunk, lines...)
	}
	if !found && src.Error == "" {
		src.Missing = true
		return src
	}
	if len(lines) > want {
		lines = lines[len(lines)-want:]
	}
	// Filtr i obcięcie długich linii, potem limit bajtów od najstarszych.
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		if len(l) > maxLineChars {
			l = l[:maxLineChars] + "…"
		}
		l, red := Redact(l)
		if red {
			*redacted++
		}
		out = append(out, l)
	}
	total := 0
	for _, l := range out {
		total += len(l) + 1
	}
	for total > budget && len(out) > 0 {
		total -= len(out[0]) + 1
		out = out[1:]
		src.Truncated = true
	}
	src.Lines = out
	return src
}

// tailLines zwraca ostatnie n pełnych linii pliku (ostatnie maxFileRead bajtów).
func tailLines(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	start := int64(0)
	if st.Size() > maxFileRead {
		start = st.Size() - maxFileRead
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileRead+4096))
	if err != nil {
		return nil, err
	}
	if start > 0 {
		// Pierwsza linia mogła zostać przecięta: odrzucamy ją.
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			data = data[i+1:]
		}
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.TrimRight(text, "\n")
	if text == "" {
		return nil, nil
	}
	all := strings.Split(text, "\n")
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all, nil
}
