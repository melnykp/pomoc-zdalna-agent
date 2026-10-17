// Package ipc definiuje komunikaty między agentem a watchdogiem (docs/ARCHITECTURE.md).
//
// Wymiana odbywa się przez pliki stanu w katalogu state (JSON), a nie przez potok nazwany: oba procesy działają jako
// SYSTEM, a katalog ma ACL tylko dla SYSTEM i Administratorów. Pakiet zawiera typy komunikatów i kodowanie linii.
package ipc

import (
	"bufio"
	"encoding/json"
	"io"
)

// PipeName to nazwa potoku (docelowo z internal/config).
const PipeName = `\\.\pipe\rmm-watchdog`

// SDDL ogranicza dostęp do potoku do SYSTEM i Administratorów.
const SDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Kind to rodzaj komunikatu.
type Kind string

// Rodzaje komunikatów agent → watchdog.
const (
	KindApply    Kind = "apply"    // podmień komponent na zweryfikowany plik ze staging
	KindStatus   Kind = "status"   // podaj wersję i last_good
	KindRollback Kind = "rollback" // wróć do .prev
	KindHealth   Kind = "health"   // agent zgłasza zdrowie po starcie
)

// Request to komunikat od agenta.
type Request struct {
	Kind      Kind   `json:"kind"`
	Component string `json:"component,omitempty"`
	Path      string `json:"path,omitempty"`
	Version   string `json:"version,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// Response to odpowiedź watchdoga.
type Response struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Version  string `json:"version,omitempty"`
	LastGood string `json:"last_good,omitempty"`
}

// WriteLine zapisuje v jako jedną linię JSON.
func WriteLine(w io.Writer, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(raw, '\n'))
	return err
}

// ReadLine czyta jedną linię JSON do v.
func ReadLine(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil && (err != io.EOF || len(line) == 0) {
		return err
	}
	return json.Unmarshal(line, v)
}
