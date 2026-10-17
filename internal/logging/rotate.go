package logging

import (
	"fmt"
	"os"
	"sync"
)

// rotator to plik logu z rotacją po rozmiarze: agent.log, agent.log.1 ... agent.log.<keep>.
// Najstarszy plik jest usuwany, więc logi nie zapełnią dysku klienta.
type rotator struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
	max  int64
	keep int
}

func newRotator(path string, maxBytes int64, keep int) (*rotator, error) {
	r := &rotator{path: path, max: maxBytes, keep: keep}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotator) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotator) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		if err := r.rotate(); err != nil {
			// Rotacja nieudana (np. plik zablokowany): piszemy dalej do bieżącego pliku, logi nie mogą zatrzymać agenta.
			n, werr := r.f.Write(p)
			r.size += int64(n)
			return n, werr
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotator) rotate() error {
	if err := r.f.Close(); err != nil {
		return err
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.keep))
	for i := r.keep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", r.path, i), fmt.Sprintf("%s.%d", r.path, i+1))
	}
	renameErr := os.Rename(r.path, r.path+".1")
	if err := r.open(); err != nil {
		return err
	}
	return renameErr
}

func (r *rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.f.Close()
}
