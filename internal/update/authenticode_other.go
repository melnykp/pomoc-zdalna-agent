//go:build !windows

package update

// verifyAuthenticode: Authenticode istnieje tylko w Windows. Poza nim build musi mieć RequireAuthenticode=false
// (rozwój, testy, CI), inaczej aktualizacja jest odrzucana.
func verifyAuthenticode(string) (string, error) { return "", ErrNoAuthenticode }
