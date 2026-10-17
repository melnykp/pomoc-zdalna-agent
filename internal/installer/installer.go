// Package installer realizuje tryb instalatora (docs/ARCHITECTURE.md):
// ten sam podpisany agent.exe uruchomiony z pulpitu instaluje się sam, czytając token
// zaproszenia z adresu pobrania zapisanego przy pliku (Zone.Identifier) albo z własnej nazwy
// pliku (<Nazwa>-Setup-<token>.exe).
package installer

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Token zaproszenia to 32 bajty w base64url bez dopełnienia (43 znaki); dopuszczamy 32..64.
// Przeglądarka dopisuje " (1)" do ponownie pobranego pliku, więc ten przyrostek jest dozwolony przed rozszerzeniem.
var tokenRe = regexp.MustCompile(`(?i)-setup-([A-Za-z0-9_-]{32,64})(?: \(\d{1,3}\))?\.exe$`)

// TokenFromFilename wyciąga token zaproszenia z nazwy pliku instalatora.
func TokenFromFilename(name string) (string, bool) {
	m := tokenRe.FindStringSubmatch(filepath.Base(name))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// urlTokenRe wyciąga token z adresu strony zaproszenia (/i/<token>) albo pobrania (/i/<token>/<plik>.exe).
var urlTokenRe = regexp.MustCompile(`/i/([A-Za-z0-9_-]{32,64})(?:[/?#]|$)`)

// TokenFromZoneIdentifier wyciąga token z zawartości strumienia Zone.Identifier („plik pochodzi z internetu”).
// Chrome, Edge i Firefox zapisują w nim adres pobrania (HostUrl) i adres strony, z której kliknięto (ReferrerUrl),
// więc plik o krótkiej, stałej nazwie nadal wie, z jakiego zaproszenia pochodzi.
func TokenFromZoneIdentifier(content string) (string, bool) {
	for _, line := range strings.Split(content, "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || (key != "HostUrl" && key != "ReferrerUrl") {
			continue
		}
		if m := urlTokenRe.FindStringSubmatch(strings.TrimSpace(val)); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// tokenFromZoneIdentifierFile czyta strumień Zone.Identifier pliku (tylko Windows, NTFS). Rozmiar jest ograniczony,
// bo zawartość pochodzi z zewnątrz.
func tokenFromZoneIdentifierFile(path string) (string, bool) {
	if runtime.GOOS != "windows" {
		return "", false
	}
	f, err := os.Open(path + ":Zone.Identifier")
	if err != nil {
		return "", false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8192))
	if err != nil {
		return "", false
	}
	return TokenFromZoneIdentifier(string(b))
}

// TokenFromExecutable wyciąga token zaproszenia z bieżącego pliku wykonywalnego: najpierw z jego nazwy
// (<Nazwa>-Setup-<token>.exe, działa też bez przeglądarki), potem z adresu pobrania zapisanego przy pliku.
func TokenFromExecutable() (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	if t, ok := TokenFromFilename(exe); ok {
		return t, true
	}
	return tokenFromZoneIdentifierFile(exe)
}

// bareTokenRe rozpoznaje sam token wklejony przez użytkownika.
var bareTokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

// TokenFromText wyciąga token zaproszenia z tekstu wklejonego przez użytkownika: sam token, cały adres zaproszenia
// (/i/<token>) albo nazwa pliku instalatora z tokenem.
func TokenFromText(s string) (string, bool) {
	s = strings.Trim(strings.TrimSpace(s), "\"'")
	if bareTokenRe.MatchString(s) {
		return s, true
	}
	if m := urlTokenRe.FindStringSubmatch(s); m != nil {
		return m[1], true
	}
	return TokenFromFilename(s)
}
