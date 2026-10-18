package peer

import "testing"

const sampleFP = "4A:AD:B9:B1:3F:82:18:3B:54:02:12:DF:3E:5D:49:6B:19:E5:7C:AB:3E:0E:64:B4:8B:A4:9D:D3:11:1D:4F:0C"

func TestFingerprintFindsSessionLevelAttribute(t *testing.T) {
	sdp := "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\na=fingerprint:sha-256 " + sampleFP + "\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
	if got := Fingerprint(sdp); got != sampleFP {
		t.Fatalf("odcisk %q", got)
	}
}

func TestFingerprintAcceptsLowercaseAndMediaLevel(t *testing.T) {
	low := "4a:ad:b9:b1:3f:82:18:3b:54:02:12:df:3e:5d:49:6b:19:e5:7c:ab:3e:0e:64:b4:8b:a4:9d:d3:11:1d:4f:0c"
	sdp := "v=0\nm=video 9 UDP/TLS/RTP/SAVPF 96\na=fingerprint:sha-256 " + low + "\n"
	if got := Fingerprint(sdp); got != sampleFP {
		t.Fatalf("odcisk %q", got)
	}
}

func TestFingerprintRejectsOtherHashesAndGarbage(t *testing.T) {
	if Fingerprint("a=fingerprint:sha-1 AB:CD\n") != "" {
		t.Fatal("sha-1 nie jest akceptowany")
	}
	if Fingerprint("a=fingerprint:sha-256 AB:CD\n") != "" {
		t.Fatal("za krótki odcisk nie jest akceptowany")
	}
	if Fingerprint("") != "" {
		t.Fatal("puste SDP")
	}
}

const otherFP = "53:4C:B1:53:D5:BF:F7:0C:6B:D2:27:CB:33:97:67:0C:BD:52:EB:BF:AA:E5:6B:A3:85:1F:6F:9E:2A:89:46:C4"

func TestFingerprintRequiresSingleSHA256AcrossWholeSDP(t *testing.T) {
	// Ten sam odcisk powtórzony w każdym medium (tak robi Chrome z BUNDLE) jest w porządku.
	same := "v=0\r\na=fingerprint:sha-256 " + sampleFP + "\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 " + sampleFP + "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 " + sampleFP + "\r\n"
	if got := Fingerprint(same); got != sampleFP {
		t.Fatalf("powtórzony odcisk: %q", got)
	}
	// Inny algorytm obok sha-256 (atak: druga strona bierze inną linię) dyskwalifikuje całe SDP.
	mixed := "v=0\r\na=fingerprint:sha-512 AB:CD:EF\r\na=fingerprint:sha-256 " + sampleFP + "\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\n"
	if Fingerprint(mixed) != "" {
		t.Fatal("sha-512 obok sha-256 musi dać pusty odcisk")
	}
	// Dwa różne odciski sha-256 (sesja i medium) też.
	two := "v=0\r\na=fingerprint:sha-256 " + sampleFP + "\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=fingerprint:sha-256 " + otherFP + "\r\n"
	if Fingerprint(two) != "" {
		t.Fatal("dwa różne odciski muszą dać pusty odcisk")
	}
	// Uszkodzona linia fingerprint między poprawnymi też.
	broken := "v=0\r\na=fingerprint:sha-256 " + sampleFP + "\r\na=fingerprint:\r\n"
	if Fingerprint(broken) != "" {
		t.Fatal("uszkodzona linia musi dać pusty odcisk")
	}
}

func TestCertificateFingerprintMatchesSDPFormat(t *testing.T) {
	fp := CertificateFingerprint([]byte("certyfikat"))
	if len(fp) != 95 || !fingerprintHexRe.MatchString(fp) {
		t.Fatalf("zapis odcisku: %q", fp)
	}
	if fp != CertificateFingerprint([]byte("certyfikat")) || fp == CertificateFingerprint([]byte("inny")) {
		t.Fatal("odcisk musi być deterministyczny i zależny od treści")
	}
}
