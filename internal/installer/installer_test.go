package installer

import "testing"

func TestTokenFromZoneIdentifier(t *testing.T) {
	const token = "k3Jx9QpL0vT2mN8sB4wZ7cH1yD6fG5aR-eU_oI3nM9q"
	good := []string{
		// Tak zapisuje Chrome: adres strony i adres pobrania, końce wierszy CRLF.
		"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://agent.example.pl/i/" + token + "\r\nHostUrl=https://agent.example.pl/i/" + token + "/Setup.exe\r\n",
		"[ZoneTransfer]\nZoneId=3\nHostUrl=https://agent.example.pl/i/" + token + "/Setup.exe\n",
		"[ZoneTransfer]\nZoneId=3\nReferrerUrl=https://agent.example.pl/i/" + token + "?x=1\n",
	}
	for _, content := range good {
		got, ok := TokenFromZoneIdentifier(content)
		if !ok || got != token {
			t.Errorf("%q: ok=%v token=%q", content, ok, got)
		}
	}

	bad := []string{
		"",
		"[ZoneTransfer]\r\nZoneId=3\r\n",
		"[ZoneTransfer]\nZoneId=3\nHostUrl=https://agent.example.pl/i/krotki/Setup.exe\n",
		"[ZoneTransfer]\nZoneId=3\nHostUrl=https://agent.example.pl/api/" + token + "\n",
		// Token w innym polu niż adresy pobrania i strony nie jest brany pod uwagę.
		"[ZoneTransfer]\nZoneId=3\nOpis=https://agent.example.pl/i/" + token + "\n",
	}
	for _, content := range bad {
		if got, ok := TokenFromZoneIdentifier(content); ok {
			t.Errorf("%q: nie powinno dać tokenu, dało %q", content, got)
		}
	}
}

func TestTokenFromFilename(t *testing.T) {
	const token = "k3Jx9QpL0vT2mN8sB4wZ7cH1yD6fG5aR-eU_oI3nM9q"
	good := []string{
		"RMM-Setup-" + token + ".exe",
		`C:\Users\klient\Downloads\RMM-Setup-` + token + ".exe",
		"/tmp/PomocIT-setup-" + token + ".EXE",
		`C:\Users\klient\Downloads\RMM-Setup-` + token + " (1).exe",
		"RMM-Setup-" + token + " (12).exe",
	}
	for _, name := range good {
		got, ok := TokenFromFilename(name)
		if !ok || got != token {
			t.Errorf("%s: ok=%v token=%q", name, ok, got)
		}
	}

	bad := []string{
		"RMM-Setup.exe",
		"RMM-Setup-krotki.exe",
		"RMM-Setup-" + token + ".msi",
		"RMM-Setup-" + token + " (x).exe",
		"RMM-Setup-" + token + " (1234).exe",
		"RMM-Setup-" + token + " kopia.exe",
		"RMM-Setup-zly token ze spacja aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.exe",
		"agent.exe",
	}
	for _, name := range bad {
		if got, ok := TokenFromFilename(name); ok {
			t.Errorf("%s: nie powinno dać tokenu, dało %q", name, got)
		}
	}
}

func TestTokenFromText(t *testing.T) {
	const token = "k3Jx9QpL0vT2mN8sB4wZ7cH1yD6fG5aR-eU_oI3nM9q"
	good := []string{
		token,
		"  " + token + "\r\n",
		`"` + token + `"`,
		"https://agent.example.pl/i/" + token,
		"https://agent.example.pl/i/" + token + "/Piotr-Melnyk-IT-POMOC-Zdalna-Setup.exe",
		"Piotr-Melnyk-IT-POMOC-Zdalna-Setup-" + token + ".exe",
	}
	for _, s := range good {
		got, ok := TokenFromText(s)
		if !ok || got != token {
			t.Errorf("%q: ok=%v token=%q", s, ok, got)
		}
	}
	for _, s := range []string{"", "   ", "krotki", "zly token ze spacja aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "https://agent.example.pl/api/" + token} {
		if got, ok := TokenFromText(s); ok {
			t.Errorf("%q: nie powinno dać tokenu, dało %q", s, got)
		}
	}
}
