package peer

// PathMsg to komunikat kanału "meta" o ścieżce przechwytywania: widz pokazuje tryb awaryjny, gdy Degraded jest prawdą,
// żeby wolniejszy obraz bez części okien (GDI) nie wyglądał jak zawieszony komputer.
type PathMsg struct {
	T        string `json:"t"` // zawsze "path"
	Path     string `json:"path"`
	Degraded bool   `json:"degraded"`
	Reason   string `json:"reason,omitempty"`
}

// NewPathMsg buduje komunikat o ścieżce.
func NewPathMsg(path string, degraded bool, reason string) PathMsg {
	if len(reason) > 200 {
		reason = reason[:200]
	}
	return PathMsg{T: "path", Path: path, Degraded: degraded, Reason: reason}
}
