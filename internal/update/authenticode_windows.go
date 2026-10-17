//go:build windows

package update

import (
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

var (
	modCrypt32                      = windows.NewLazySystemDLL("crypt32.dll")
	procCryptMsgGetParam            = modCrypt32.NewProc("CryptMsgGetParam")
	procCryptMsgClose               = modCrypt32.NewProc("CryptMsgClose")
	procCertGetSubjectCertFromStore = modCrypt32.NewProc("CertGetSubjectCertificateFromStore")
)

const (
	cmsgSignerCertInfoParam = 7       // CMSG_SIGNER_CERT_INFO_PARAM
	certEncodingX509AndP7   = 0x10001 // X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
)

// signerSubject czyta podmiot certyfikatu, którym plik podpisano. Podpisującego wskazuje SignerInfo komunikatu PKCS#7
// (wystawca i numer seryjny), a nie zgadywanie z magazynu: obok certyfikatu podpisującego leży w nim łańcuch oraz
// certyfikat urzędu znacznika czasu, który też niczego nie wystawia i dałby fałszywy wynik. Każdy błąd odrzuca plik.
func signerSubject(path string) (string, error) {
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var store, msg windows.Handle
	err = windows.CryptQueryObject(
		windows.CERT_QUERY_OBJECT_FILE,
		unsafe.Pointer(p16),
		windows.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		windows.CERT_QUERY_FORMAT_FLAG_BINARY,
		0, nil, nil, nil, &store, &msg, nil,
	)
	if err != nil {
		return "", fmt.Errorf("%w: odczyt podpisu: %v", ErrNoAuthenticode, err)
	}
	defer windows.CertCloseStore(store, 0)
	defer procCryptMsgClose.Call(uintptr(msg))

	// Pierwsze wywołanie podaje rozmiar, drugie wypełnia CERT_INFO (wskaźniki w nim wskazują do tego samego bufora).
	var size uint32
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, 0, uintptr(unsafe.Pointer(&size))); r == 0 || size == 0 {
		return "", fmt.Errorf("%w: brak danych podpisującego: %v", ErrNoAuthenticode, e)
	}
	buf := make([]byte, size)
	if r, _, e := procCryptMsgGetParam.Call(uintptr(msg), cmsgSignerCertInfoParam, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))); r == 0 {
		return "", fmt.Errorf("%w: odczyt danych podpisującego: %v", ErrNoAuthenticode, e)
	}
	ctx, _, e := procCertGetSubjectCertFromStore.Call(uintptr(store), certEncodingX509AndP7, uintptr(unsafe.Pointer(&buf[0])))
	if ctx == 0 {
		return "", fmt.Errorf("%w: certyfikatu podpisującego nie ma w podpisie: %v", ErrNoAuthenticode, e)
	}
	cc := *(**windows.CertContext)(unsafe.Pointer(&ctx)) // wskaźnik zwrócony przez API, nie arytmetyka na adresie
	defer windows.CertFreeCertificateContext(cc)
	if cc.EncodedCert == nil || cc.Length == 0 {
		return "", fmt.Errorf("%w: pusty certyfikat podpisującego", ErrNoAuthenticode)
	}
	// Kopia bajtów: pamięć kontekstu jest zwalniana razem z kontekstem.
	der := append([]byte(nil), unsafe.Slice(cc.EncodedCert, cc.Length)...)
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("%w: certyfikat podpisującego: %v", ErrNoAuthenticode, err)
	}
	return cert.Subject.String(), nil
}
