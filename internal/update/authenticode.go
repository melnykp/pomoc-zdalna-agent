package update

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// RequireAuthenticode steruje sprawdzaniem podpisu Authenticode plików wydań. Build produkcyjny zostawia
// „true”. Build rozwojowy i pilotażowy bez certyfikatu kodu ustawia „false” przez
//
//	-ldflags "-X github.com/melnykp/pomoc-zdalna-agent/internal/update.RequireAuthenticode=false"
//
// i wtedy o zaufaniu do pliku decydują podpis sshsig manifestu oraz suma SHA-256, nie podpis producenta.
var RequireAuthenticode = "true"

// AuthenticodeRequired mówi, czy plik wydania musi mieć ważny podpis Authenticode.
func AuthenticodeRequired() bool { return RequireAuthenticode != "false" }

// ErrNoAuthenticode oznacza platformę albo plik bez możliwości sprawdzenia podpisu.
var ErrNoAuthenticode = errors.New("update: brak podpisu Authenticode")

// CheckSignature sprawdza podpis Authenticode pliku zgodnie z polityką builda. Podmiot certyfikatu musi
// zgadzać się z zapisanym w manifeście.
func CheckSignature(path, wantSubject string) error {
	if !AuthenticodeRequired() {
		return nil
	}
	got, err := verifyAuthenticode(path)
	if err != nil {
		return err
	}
	if !SubjectsEqual(got, wantSubject) {
		return fmt.Errorf("update: podmiot certyfikatu %q, manifest %q", got, wantSubject)
	}
	return nil
}

// SubjectsEqual porównuje nazwy podmiotów niezależnie od kolejności składników i wielkości liter w nazwach
// atrybutów: Windows podaje „CN=Firma, O=Firma, C=PL”, a manifest może mieć inną kolejność.
func SubjectsEqual(a, b string) bool {
	na, nb := normalizeSubject(a), normalizeSubject(b)
	return na != "" && na == nb
}

func normalizeSubject(s string) string {
	var parts []string
	for _, p := range splitRDN(s) {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return ""
		}
		k = strings.ToUpper(strings.TrimSpace(k))
		if k == "S" { // Windows pisze S, Go i OpenSSL ST: to samo województwo
			k = "ST"
		}
		parts = append(parts, k+"="+unquoteRDN(strings.TrimSpace(v)))
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// unquoteRDN zdejmuje cudzysłowy i znaki ucieczki z wartości RDN, żeby "Firma\, sp." i "Firma, sp." były równe.
func unquoteRDN(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	var sb strings.Builder
	esc := false
	for _, r := range v {
		if esc {
			sb.WriteRune(r)
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// splitRDN dzieli po przecinkach poza cudzysłowami i poza znakiem ucieczki (\,).
func splitRDN(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote, esc := false, false
	for _, r := range s {
		switch {
		case esc:
			cur.WriteRune(r)
			esc = false
		case r == '\\':
			cur.WriteRune(r)
			esc = true
		case r == '"':
			inQuote = !inQuote
			cur.WriteRune(r)
		case r == ',' && !inQuote:
			if t := strings.TrimSpace(cur.String()); t != "" {
				out = append(out, t)
			}
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if t := strings.TrimSpace(cur.String()); t != "" {
		out = append(out, t)
	}
	return out
}
