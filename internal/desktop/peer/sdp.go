// Package peer to połączenie WebRTC pomocnika pulpitu z jednym widzem: ścieżka wideo H.264 (RTP) i kanały danych
// (wejście od widza, kursor i metadane do widza). Pliki bez znacznika platformy da się testować wszędzie.
package peer

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
)

var (
	fingerprintLineRe  = regexp.MustCompile(`(?mi)^a=fingerprint:.*$`)
	fingerprintValueRe = regexp.MustCompile(`(?i)^a=fingerprint:(\S+)\s+(\S+)\s*$`)
	fingerprintHexRe   = regexp.MustCompile(`^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$`)
)

// Fingerprint wyciąga z SDP odcisk DTLS sha-256 (wielkimi literami, z dwukropkami) albo pusty tekst. Wszystkie linie
// `a=fingerprint` (poziom sesji i każde medium) muszą być sha-256 i identyczne: inny algorytm obok sha-256 albo dwa
// różne odciski oznaczają SDP, którego druga strona może zinterpretować inaczej niż my, więc odrzucamy je w całości.
// Odcisk przypina serwer do sesji: druga strona sprawdza certyfikat DTLS właśnie z nim (standard WebRTC), więc
// uwierzytelniony kanał sygnalizacji przenosi tożsamość na połączenie medialne.
func Fingerprint(sdp string) string {
	found := ""
	for _, line := range fingerprintLineRe.FindAllString(sdp, -1) {
		m := fingerprintValueRe.FindStringSubmatch(strings.TrimRight(line, "\r"))
		if m == nil || !strings.EqualFold(m[1], "sha-256") {
			return ""
		}
		fp := strings.ToUpper(m[2])
		if !fingerprintHexRe.MatchString(fp) || (found != "" && found != fp) {
			return ""
		}
		found = fp
	}
	return found
}

// CertificateFingerprint liczy odcisk sha-256 certyfikatu DER w zapisie SDP (do porównania z przypiętym odciskiem).
func CertificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}
