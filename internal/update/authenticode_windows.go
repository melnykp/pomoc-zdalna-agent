//go:build windows

package update

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// verifyAuthenticode sprawdza łańcuch Authenticode przez WinVerifyTrust (bez interfejsu użytkownika) i zwraca
// nazwę podmiotu certyfikatu, którym plik podpisano. Odwołania listy CRL nie są sprawdzane (wymagałyby sieci
// w usłudze); wycofanie wadliwego wydania załatwia mechanizm yank, a nie lista odwołań.
func verifyAuthenticode(path string) (string, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	file := &windows.WinTrustFileInfo{Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: p16}
	data := &windows.WinTrustData{
		Size:                            uint32(unsafe.Sizeof(windows.WinTrustData{})),
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(file),
	}
	verifyErr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data)
	if verifyErr != nil {
		return "", fmt.Errorf("%w: %v", ErrNoAuthenticode, verifyErr)
	}
	return signerSubject(path)
}

// signerSubject czyta certyfikat podpisującego z osadzonego podpisu pliku. W magazynie komunikatu PKCS#7 leży
// certyfikat podpisującego i jego łańcuch, a podpisującym jest ten, który niczego nie wystawił pozostałym.
func signerSubject(path string) (string, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var store windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(p16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0, nil, nil, nil, &store, nil, nil,
	)
	if err != nil {
		return "", fmt.Errorf("%w: odczyt podpisu: %v", ErrNoAuthenticode, err)
	}
	defer windows.CertCloseStore(store, 0)

	var certs []*x509.Certificate
	var prev *windows.CertContext
	for {
		c, err := windows.CertEnumCertificatesInStore(store, prev)
		if err != nil || c == nil {
			break
		}
		prev = c
		if c.EncodedCert == nil || c.Length == 0 {
			continue
		}
		// Kopia bajtów: pamięć kontekstu należy do magazynu i jest zwalniana przy jego zamknięciu.
		der := append([]byte(nil), unsafe.Slice(c.EncodedCert, c.Length)...)
		if cert, err := x509.ParseCertificate(der); err == nil {
			certs = append(certs, cert)
		}
	}
	for _, c := range certs {
		isIssuer := false
		for _, o := range certs {
			if o != c && bytes.Equal(o.RawIssuer, c.RawSubject) {
				isIssuer = true
				break
			}
		}
		if !isIssuer {
			return c.Subject.String(), nil
		}
	}
	return "", fmt.Errorf("%w: brak certyfikatu podpisującego", ErrNoAuthenticode)
}
