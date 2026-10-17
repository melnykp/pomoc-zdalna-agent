// Package releasesig weryfikuje podpisy manifestów wydań (docs/ARCHITECTURE.md).
//
// Podpisy są w formacie sshsig (ssh-keygen -Y sign, przestrzeń nazw Namespace) i pochodzą z kluczy ssh-ed25519 albo
// sk-ssh-ed25519 (klucz sprzętowy), a lista zaufanych kluczy jest wkompilowana w agenta (patrz sshsig.go, TrustedSigners).
// Surowy Ed25519 w tym pliku (SignRaw, VerifyRaw) służy tylko testom.
package releasesig

import (
	"crypto/ed25519"
	"errors"
)

// Namespace to przestrzeń nazw podpisu (parametr -n w ssh-keygen -Y sign).
const Namespace = "rmm-release"

// AllowedSigner to zaufany klucz podpisu wydań.
type AllowedSigner struct {
	KeyID     string
	PublicKey ed25519.PublicKey
}

var (
	// ErrUntrustedKey: identyfikator klucza nie jest na liście zaufanych.
	ErrUntrustedKey = errors.New("releasesig: klucz podpisu nie jest na liście zaufanych")
	// ErrBadSignature: podpis nie pasuje do manifestu.
	ErrBadSignature = errors.New("releasesig: zły podpis manifestu")
)

// signedBytes buduje bajty podpisywane w trybie surowym: Namespace, bajt 0, manifest.
func signedBytes(manifest []byte) []byte {
	out := make([]byte, 0, len(Namespace)+1+len(manifest))
	out = append(out, Namespace...)
	out = append(out, 0)
	return append(out, manifest...)
}

// SignRaw podpisuje manifest surowym Ed25519 (tryb testowy i narzędziowy).
func SignRaw(priv ed25519.PrivateKey, manifest []byte) []byte {
	return ed25519.Sign(priv, signedBytes(manifest))
}

// VerifyRaw sprawdza surowy podpis Ed25519 kluczem o identyfikatorze keyID.
func VerifyRaw(manifest, sig []byte, keyID string, signers []AllowedSigner) error {
	for _, s := range signers {
		if s.KeyID != keyID {
			continue
		}
		if len(s.PublicKey) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return ErrBadSignature
		}
		if ed25519.Verify(s.PublicKey, signedBytes(manifest), sig) {
			return nil
		}
		return ErrBadSignature
	}
	return ErrUntrustedKey
}

// Embedded to pozostałość szkieletu (zawsze pusta). Zaufane klucze zwraca TrustedSigners (sshsig.go);
// ta funkcja zostanie usunięta.
func Embedded() []AllowedSigner {
	return nil
}
