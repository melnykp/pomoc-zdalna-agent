//go:build windows

package identity

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// entropy to stały dodatek do szyfrowania: blok zaszyfrowany DPAPI dla tego programu nie odszyfruje się
// przypadkiem w innym, który też używa DPAPI bez dodatku.
var entropy = []byte("pomoc-zdalna-identity-v1")

// protect szyfruje dane DPAPI w zakresie maszyny: odszyfrować je może tylko ten komputer (nie kopia pliku zabrana
// z kopii zapasowej albo z dysku). Zakres maszyny, a nie użytkownika, bo agent działa jako LocalSystem i musi
// działać bez zalogowanego użytkownika. Ochrona przed lokalnym użytkownikiem to ACL katalogu danych.
func protect(data []byte) ([]byte, bool, error) {
	in := blob(data)
	ent := blob(entropy)
	var out windows.DataBlob
	err := windows.CryptProtectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, true, fmt.Errorf("identity: DPAPI nie zaszyfrowało klucza: %w", err)
	}
	return take(&out), true, nil
}

// unprotect odszyfrowuje blok zaszyfrowany funkcją protect na tym samym komputerze.
func unprotect(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("identity: pusty blok DPAPI")
	}
	in := blob(sealed)
	ent := blob(entropy)
	var out windows.DataBlob
	err := windows.CryptUnprotectData(&in, nil, &ent, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, fmt.Errorf("identity: DPAPI nie odszyfrowało klucza (plik z innego komputera albo uszkodzony): %w", err)
	}
	return take(&out), nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// take kopiuje wynik DPAPI do pamięci Go i zwalnia bufor systemowy.
func take(out *windows.DataBlob) []byte {
	if out.Data == nil {
		return nil
	}
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return res
}
