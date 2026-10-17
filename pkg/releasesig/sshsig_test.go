package releasesig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hiddeco/sshsig"
	"golang.org/x/crypto/ssh"
)

var manifestBytes = []byte(`{"schema":1,"component":"agent","version":"1.3.0"}` + "\n")

func newSigner(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, s.PublicKey()
}

func TestSSHSigRoundTrip(t *testing.T) {
	signer, pub := newSigner(t)
	sig, err := SignSSHSig(manifestBytes, signer)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := VerifySSHSig(manifestBytes, sig, []ssh.PublicKey{pub})
	if err != nil || fp != Fingerprint(pub) {
		t.Fatalf("fp=%q err=%v", fp, err)
	}
}

func TestSSHSigRejectsTamperedManifest(t *testing.T) {
	signer, pub := newSigner(t)
	sig, _ := SignSSHSig(manifestBytes, signer)
	tampered := bytes.Replace(manifestBytes, []byte("1.3.0"), []byte("9.9.9"), 1)
	if _, err := VerifySSHSig(tampered, sig, []ssh.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("zmieniony manifest powinien dać ErrBadSignature, jest: %v", err)
	}
}

func TestSSHSigRejectsUntrustedKey(t *testing.T) {
	signer, _ := newSigner(t)
	_, other := newSigner(t)
	sig, _ := SignSSHSig(manifestBytes, signer)
	if _, err := VerifySSHSig(manifestBytes, sig, []ssh.PublicKey{other}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("podpis nieznanym kluczem powinien dać ErrUntrustedKey, jest: %v", err)
	}
	if _, err := VerifySSHSig(manifestBytes, sig, nil); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("pusta lista zaufanych kluczy nie może niczego przepuścić, jest: %v", err)
	}
}

func TestSSHSigRejectsOtherNamespace(t *testing.T) {
	signer, pub := newSigner(t)
	// Ten sam klucz podpisał ten sam tekst, ale w innej przestrzeni nazw (np. do commitów gita).
	other, err := sshsig.Sign(bytes.NewReader(manifestBytes), signer, sshsig.HashSHA512, "git")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySSHSig(manifestBytes, sshsig.Armor(other), []ssh.PublicKey{pub}); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("podpis z obcej przestrzeni nazw powinien być odrzucony, jest: %v", err)
	}
}

func TestSSHSigRejectsGarbage(t *testing.T) {
	_, pub := newSigner(t)
	for _, junk := range []string{"", "to nie jest podpis", "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----"} {
		if _, err := VerifySSHSig(manifestBytes, []byte(junk), []ssh.PublicKey{pub}); err == nil {
			t.Errorf("śmieć %q nie może przejść", junk)
		}
	}
}

func TestParseAuthorizedKeys(t *testing.T) {
	_, pub1 := newSigner(t)
	_, pub2 := newSigner(t)
	text := "# komentarz\n\n" + string(ssh.MarshalAuthorizedKey(pub1)) + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub2))) + " release-2\n"
	keys, err := ParseAuthorizedKeys(text)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%d err=%v", len(keys), err)
	}
	if _, err := ParseAuthorizedKeys("ssh-ed25519 to-nie-klucz"); err == nil {
		t.Fatal("zły klucz powinien dać błąd")
	}
}

func TestCompiledSignersSplitBySemicolon(t *testing.T) {
	_, pub1 := newSigner(t)
	_, pub2 := newSigner(t)
	CompiledSigners = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub1))) + " a;" + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub2))) + " b"
	t.Cleanup(func() { CompiledSigners = "" })
	keys, err := TrustedSigners()
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys=%d err=%v", len(keys), err)
	}
	CompiledSigners = ""
	if keys, err := TrustedSigners(); err != nil || len(keys) != 0 {
		t.Fatalf("bez wkompilowanych kluczy lista ma być pusta: %d %v", len(keys), err)
	}
}

// Zgodność z prawdziwym narzędziem, którym podpisze wydanie operator (ssh-keygen -Y sign). Pomijany bez ssh-keygen.
func TestSSHSigInteropWithSSHKeygen(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("brak ssh-keygen")
	}
	dir := t.TempDir()
	key := filepath.Join(dir, "release_key")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "release-test", "-f", key).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen nie wygenerował klucza: %v %s", err, out)
	}
	manifest := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(manifest, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(keygen, "-Y", "sign", "-f", key, "-n", Namespace, manifest).CombinedOutput(); err != nil {
		t.Skipf("ssh-keygen -Y sign niedostępny: %v %s", err, out)
	}
	sig, err := os.ReadFile(manifest + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	pubText, _ := os.ReadFile(key + ".pub")
	keys, err := ParseAuthorizedKeys(string(pubText))
	if err != nil || len(keys) != 1 {
		t.Fatalf("klucz publiczny: %v", err)
	}
	if _, err := VerifySSHSig(manifestBytes, sig, keys); err != nil {
		t.Fatalf("podpis z ssh-keygen powinien przejść: %v", err)
	}
	if _, err := VerifySSHSig(append(manifestBytes, ' '), sig, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("zmieniony manifest powinien być odrzucony: %v", err)
	}
}
