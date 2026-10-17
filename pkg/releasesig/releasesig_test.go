package releasesig

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestVerifyRaw(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signers := []AllowedSigner{{KeyID: "release-2026", PublicKey: pub}}
	manifest := []byte(`{"schema":1,"component":"agent","version":"1.0.0"}`)
	sig := SignRaw(priv, manifest)

	if err := VerifyRaw(manifest, sig, "release-2026", signers); err != nil {
		t.Fatalf("poprawny podpis odrzucony: %v", err)
	}
	if err := VerifyRaw(manifest, sig, "inny-klucz", signers); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("nieznany klucz powinien dać ErrUntrustedKey, jest %v", err)
	}
	tampered := append([]byte{}, manifest...)
	tampered[len(tampered)-2] = '1'
	if err := VerifyRaw(tampered, sig, "release-2026", signers); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("zmieniony manifest powinien dać ErrBadSignature, jest %v", err)
	}
	if err := VerifyRaw(manifest, sig[:10], "release-2026", signers); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("ucięty podpis powinien dać ErrBadSignature, jest %v", err)
	}
}

func TestParseManifest(t *testing.T) {
	good := []byte(`{
	  "schema": 1, "component": "agent", "version": "1.3.0", "os": "windows", "arch": "amd64",
	  "artifact": {"url": "https://agent.example.pl/v1/releases/artifacts/a.exe",
	               "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "size": 10},
	  "requires": {"watchdog_min": "1.0.0"},
	  "authenticode_subject": "CN=Firma, O=Firma, C=PL",
	  "released_at": "2026-11-20T10:00:00Z"
	}`)
	m, err := ParseManifest(good)
	if err != nil {
		t.Fatalf("poprawny manifest odrzucony: %v", err)
	}
	if err := m.Matches(ComponentAgent, "windows", "amd64"); err != nil {
		t.Fatal(err)
	}
	if err := m.Matches(ComponentWatchdog, "windows", "amd64"); err == nil {
		t.Fatal("manifest agenta nie może pasować do watchdoga")
	}
	if err := m.Matches(ComponentAgent, "linux", "amd64"); err == nil {
		t.Fatal("manifest windows nie może pasować do linuxa")
	}

	bad := []byte(`{"schema": 2, "component": "x", "artifact": {"sha256": "abc"}}`)
	if _, err := ParseManifest(bad); err == nil {
		t.Fatal("niekompletny manifest powinien być odrzucony")
	}
}

func TestManifestMinVersionRules(t *testing.T) {
	base := Manifest{
		Schema: SchemaVersion, Component: ComponentAgent, Version: "1.3.0", OS: "windows", Arch: "amd64",
		Artifact:            Artifact{URL: "https://x/v1/releases/artifacts/a.exe", SHA256: "0000000000000000000000000000000000000000000000000000000000000000", Size: 1},
		AuthenticodeSubject: "CN=Firma",
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("bez progu manifest jest poprawny: %v", err)
	}
	for _, ok := range []string{"", "1.0.0", "1.3.0", "1.3.0-rc1"} {
		m := base
		m.MinVersion = ok
		if err := m.Validate(); err != nil {
			t.Errorf("próg %q powinien być dozwolony: %v", ok, err)
		}
	}
	for _, bad := range []string{"1.3.1", "2.0.0", "abc", "1.3"} {
		m := base
		m.MinVersion = bad
		if err := m.Validate(); err == nil {
			t.Errorf("próg %q powinien być odrzucony", bad)
		}
	}
	m := base
	m.Version = "wersja"
	if err := m.Validate(); err == nil {
		t.Error("wersja spoza semver powinna być odrzucona")
	}
}
