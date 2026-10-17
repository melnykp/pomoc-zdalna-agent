package trust

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/melnykp/pomoc-zdalna-agent/internal/config"
)

func newKey(t *testing.T) (ed25519.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, base64.StdEncoding.EncodeToString(pub)
}

func TestKeysFromConfigWhenNotPinned(t *testing.T) {
	Compiled = ""
	pub, b64 := newKey(t)
	got, err := Keys([]config.ServerKey{{KeyID: "dev", PublicKey: b64}})
	if err != nil || len(got) != 1 || !got[0].Equal(pub) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestCompiledKeysOverrideConfig(t *testing.T) {
	pinned, pinnedB64 := newKey(t)
	_, otherB64 := newKey(t)
	Compiled = "prod=" + pinnedB64
	t.Cleanup(func() { Compiled = "" })

	got, err := Keys([]config.ServerKey{{KeyID: "x", PublicKey: otherB64}})
	if err != nil || len(got) != 1 || !got[0].Equal(pinned) {
		t.Fatalf("wkompilowany klucz powinien wygrać z konfiguracją: got=%v err=%v", got, err)
	}
}

func TestMultipleCompiledKeys(t *testing.T) {
	a, aB64 := newKey(t)
	b, bB64 := newKey(t)
	Compiled = "old=" + aB64 + ", new=" + bB64
	t.Cleanup(func() { Compiled = "" })
	got, err := Keys(nil)
	if err != nil || len(got) != 2 || !got[0].Equal(a) || !got[1].Equal(b) {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestKeysErrors(t *testing.T) {
	Compiled = ""
	if _, err := Keys(nil); err == nil {
		t.Fatal("bez żadnych kluczy powinien być błąd")
	}
	if _, err := Keys([]config.ServerKey{{KeyID: "x", PublicKey: "to-nie-base64!!"}}); err == nil {
		t.Fatal("zły base64 powinien dać błąd")
	}
	if _, err := Keys([]config.ServerKey{{KeyID: "x", PublicKey: base64.StdEncoding.EncodeToString([]byte("za krotki"))}}); err == nil {
		t.Fatal("zła długość klucza powinna dać błąd")
	}
	Compiled = "bez-formatu"
	t.Cleanup(func() { Compiled = "" })
	if _, err := Keys(nil); err == nil {
		t.Fatal("wkompilowany klucz bez id= powinien dać błąd")
	}
}
