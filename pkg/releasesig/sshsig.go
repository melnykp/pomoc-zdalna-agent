package releasesig

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

// CompiledSigners to lista zaufanych kluczy podpisu wydań w formacie authorized_keys, jeden klucz na wpis,
// wpisy rozdzielone średnikiem. Wstrzykiwana przy budowaniu:
//
//	-ldflags "-X github.com/melnykp/pomoc-zdalna-agent/pkg/releasesig.CompiledSigners=sk-ssh-ed25519@openssh.com AAAA... release-1;ssh-ed25519 AAAA... release-2"
//
// Klucz prywatny (ed25519-sk na YubiKey) nigdy nie jest w repozytorium ani na serwerze.
var CompiledSigners string

// TrustedSigners zwraca klucze zaufane z wkompilowanej listy. Pusta lista oznacza, że agent nie przyjmie
// żadnej aktualizacji.
func TrustedSigners() ([]ssh.PublicKey, error) {
	return ParseAuthorizedKeys(strings.ReplaceAll(CompiledSigners, ";", "\n"))
}

// ParseAuthorizedKeys czyta klucze publiczne w formacie authorized_keys. Puste linie i komentarze (#) są pomijane.
func ParseAuthorizedKeys(text string) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("releasesig: klucz w linii %d: %w", i+1, err)
		}
		out = append(out, key)
	}
	return out, nil
}

// Fingerprint zwraca odcisk SHA256 klucza w postaci SHA256:... jak w ssh-keygen -l.
func Fingerprint(k ssh.PublicKey) string { return ssh.FingerprintSHA256(k) }

// VerifySSHSig sprawdza podpis sshsig manifestu (plik .sig w postaci pancerzowej, jak z ssh-keygen -Y sign)
// kluczem z listy zaufanych, w przestrzeni nazw Namespace. Zwraca odcisk klucza, który podpisał. Podpis jest
// liczony po dokładnych bajtach manifestu, więc ich nie wolno przekodowywać.
func VerifySSHSig(manifest, armoredSig []byte, trusted []ssh.PublicKey) (string, error) {
	if len(trusted) == 0 {
		return "", ErrUntrustedKey
	}
	sig, err := sshsig.Unarmor(bytes.TrimSpace(armoredSig))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	if sig.PublicKey == nil {
		return "", ErrBadSignature
	}
	signer := ssh.FingerprintSHA256(sig.PublicKey)
	known := false
	for _, k := range trusted {
		if bytes.Equal(k.Marshal(), sig.PublicKey.Marshal()) {
			known = true
			if err := sshsig.Verify(bytes.NewReader(manifest), sig, k, sig.HashAlgorithm, Namespace); err != nil {
				return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
			}
			break
		}
	}
	if !known {
		return "", fmt.Errorf("%w (%s)", ErrUntrustedKey, signer)
	}
	return signer, nil
}

// SignSSHSig podpisuje manifest podanym podpisującym (testy i narzędzia; produkcyjnie podpisuje ssh-keygen
// z kluczem na YubiKey). Zwraca podpis w postaci pancerzowej.
func SignSSHSig(manifest []byte, signer ssh.Signer) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("releasesig: brak podpisującego")
	}
	sig, err := sshsig.Sign(bytes.NewReader(manifest), signer, sshsig.HashSHA512, Namespace)
	if err != nil {
		return nil, err
	}
	return sshsig.Armor(sig), nil
}
