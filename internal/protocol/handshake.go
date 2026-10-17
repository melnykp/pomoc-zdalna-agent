// Package protocol realizuje handshake z docs/ARCHITECTURE.md: wzajemne
// uwierzytelnienie agenta i serwera podpisami Ed25519 nad nonce'ami obu stron.
package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"

	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// NewNonce zwraca 32 losowe bajty w base64url (bez dopełnienia).
func NewNonce() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// authMessage buduje bajty do podpisu. Każde pole poprzedza jego długość (4 bajty,
// big-endian), więc przesunięcie granicy między polami nie daje tej samej wiadomości.
// Plan zapisuje to skrótowo jako konkatenację "||".
func authMessage(domain, serverNonce, agentNonce, deviceID string) []byte {
	parts := []string{domain, serverNonce, agentNonce, deviceID}
	n := 0
	for _, p := range parts {
		n += 4 + len(p)
	}
	out := make([]byte, 0, n)
	var l [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(l[:], uint32(len(p)))
		out = append(out, l[:]...)
		out = append(out, p...)
	}
	return out
}

func verify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// SignAgentAuth podpisuje wiadomość auth kluczem urządzenia.
func SignAgentAuth(priv ed25519.PrivateKey, serverNonce, agentNonce, deviceID string) []byte {
	return ed25519.Sign(priv, authMessage(wire.AuthDomainAgent, serverNonce, agentNonce, deviceID))
}

// VerifyAgentAuth weryfikuje podpis agenta (implementacja referencyjna dla serwera i testów).
func VerifyAgentAuth(pub ed25519.PublicKey, serverNonce, agentNonce, deviceID string, sig []byte) bool {
	return verify(pub, authMessage(wire.AuthDomainAgent, serverNonce, agentNonce, deviceID), sig)
}

// SignServerAuth podpisuje auth.ok kluczem serwera (implementacja referencyjna dla serwera i testów).
func SignServerAuth(priv ed25519.PrivateKey, serverNonce, agentNonce, deviceID string) []byte {
	return ed25519.Sign(priv, authMessage(wire.AuthDomainServer, serverNonce, agentNonce, deviceID))
}

// VerifyServerAuth sprawdza, że auth.ok pochodzi od serwera z zaufanym kluczem.
func VerifyServerAuth(pub ed25519.PublicKey, serverNonce, agentNonce, deviceID string, sig []byte) bool {
	return verify(pub, authMessage(wire.AuthDomainServer, serverNonce, agentNonce, deviceID), sig)
}

// EncodeSig koduje podpis do pola Sig w wiadomościach.
func EncodeSig(sig []byte) string { return base64.StdEncoding.EncodeToString(sig) }

// DecodeSig dekoduje pole Sig.
func DecodeSig(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
