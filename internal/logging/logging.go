// Package logging konfiguruje logi agenta (docs/ARCHITECTURE.md): JSON do pliku
// w katalogu danych i równolegle na stderr. Bez treści ekranu, klawiszy i sekretów.
//
// Rotacja: 5 plików po 5 MB.
package logging

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Setup otwiera plik logu z rotacją name w katalogu dir i zwraca logger oraz funkcję zamykającą.
func Setup(dir, name, level string) (*slog.Logger, func() error, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	f, err := newRotator(filepath.Join(dir, name), 5<<20, 5)
	if err != nil {
		return nil, nil, err
	}
	h := slog.NewJSONHandler(io.MultiWriter(f, os.Stderr), &slog.HandlerOptions{Level: ParseLevel(level)})
	return slog.New(h), f.Close, nil
}

// ParseLevel mapuje nazwę poziomu na slog.Level; nieznana nazwa daje Info.
func ParseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
