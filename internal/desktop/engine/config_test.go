package engine

import "testing"

func TestNormalizedFillsDefaults(t *testing.T) {
	c := Config{}.normalized()
	if c.FPS != DefaultFPS || c.Kbps != DefaultKbps || c.Encoder != "auto" || c.Path != PathAuto || c.Workers != 4 {
		t.Fatalf("domyślne: %+v", c)
	}
	// Klatki poza zakresem wracają do wartości domyślnej, a nie do granicy: 0 i 1000 to błędy, nie życzenia.
	if got := (Config{FPS: 1000}).normalized().FPS; got != DefaultFPS {
		t.Fatalf("fps 1000 → %d", got)
	}
	if got := (Config{FPS: FastFPS}).normalized().FPS; got != FastFPS {
		t.Fatalf("fps 60 → %d", got)
	}
}
