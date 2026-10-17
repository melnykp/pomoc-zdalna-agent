//go:build !windows

package identity

import "errors"

// protect poza Windows nie szyfruje (agent produkcyjny działa tylko w Windows): plik zostaje zwykłym tekstem
// z uprawnieniami 0600, tak jak w trybie rozwojowym.
func protect([]byte) ([]byte, bool, error) { return nil, false, nil }

// unprotect poza Windows nie odszyfruje bloku DPAPI.
func unprotect([]byte) ([]byte, error) {
	return nil, errors.New("identity: plik zaszyfrowany DPAPI można odczytać tylko w Windows na tym samym komputerze")
}
