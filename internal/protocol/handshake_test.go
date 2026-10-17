package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestMutualAuthRoundTrip(t *testing.T) {
	devPub, devPriv := keys(t)
	srvPub, srvPriv := keys(t)
	sn, _ := NewNonce()
	an, _ := NewNonce()
	const dev = "7a0d1c2e-0000-4000-8000-000000000001"

	agentSig := SignAgentAuth(devPriv, sn, an, dev)
	if !VerifyAgentAuth(devPub, sn, an, dev, agentSig) {
		t.Fatal("podpis agenta nie weryfikuje się")
	}
	serverSig := SignServerAuth(srvPriv, sn, an, dev)
	if !VerifyServerAuth(srvPub, sn, an, dev, serverSig) {
		t.Fatal("podpis serwera nie weryfikuje się")
	}

	// Podpis agenta nie może uchodzić za podpis serwera (różne domeny).
	if VerifyServerAuth(devPub, sn, an, dev, agentSig) {
		t.Fatal("podpis agenta przyjęty jako podpis serwera")
	}
	// Zmiana dowolnego pola unieważnia podpis.
	if VerifyAgentAuth(devPub, sn, an, "inne-urzadzenie", agentSig) {
		t.Fatal("podpis przyjęty dla innego device_id")
	}
	if VerifyAgentAuth(devPub, an, sn, dev, agentSig) {
		t.Fatal("podpis przyjęty po zamianie nonce'ów")
	}
	// Zły rozmiar klucza lub podpisu nie może spowodować paniki.
	if VerifyAgentAuth(devPub[:10], sn, an, dev, agentSig) || VerifyAgentAuth(devPub, sn, an, dev, agentSig[:5]) {
		t.Fatal("uszkodzone dane przyjęte")
	}
}

func TestAuthMessageFieldBoundaries(t *testing.T) {
	// "ab"+"c" i "a"+"bc" muszą dawać różne wiadomości.
	m1 := authMessage("d", "ab", "c", "x")
	m2 := authMessage("d", "a", "bc", "x")
	if string(m1) == string(m2) {
		t.Fatal("granice pól nie są chronione")
	}
}

func TestSigEncoding(t *testing.T) {
	_, priv := keys(t)
	sig := SignAgentAuth(priv, "s", "a", "d")
	back, err := DecodeSig(EncodeSig(sig))
	if err != nil || string(back) != string(sig) {
		t.Fatal("kodowanie podpisu nie jest odwracalne")
	}
}
