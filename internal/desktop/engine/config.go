// Package engine to pętla przechwytywania i kodowania własnego silnika pulpitu (docs/adr/0009-wlasny-silnik-pulpitu.md):
// DXGI Desktop Duplication → konwersja BGRA→NV12 → H.264 z Media Foundation → ujście (WebRTC). Ścieżka GPU
// (VideoProcessor + tekstura do kodera sprzętowego) jest domyślna, ze zejściem na kopię do RAM (koder dowolny), a na
// końcu na GDI. Kursor idzie osobno (Sink.Pointer), bo DXGI nie wkłada go do obrazu. Sama pętla jest tylko dla Windows;
// ten plik trzyma konfigurację, żeby dało się ją testować wszędzie.
package engine

// Domyślne parametry strumienia: 30 kl./s (pomiar w prototypie: o jedną trzecią mniej procesora niż 60), 6 Mb/s CBR.
const (
	DefaultFPS  = 30
	FastFPS     = 60
	DefaultKbps = 6000
	minFPS      = 5
	maxFPS      = 60
)

// Ścieżki potoku.
const (
	PathAuto = "auto"
	PathGPU  = "gpu" // VideoProcessor + tekstura NV12 do kodera sprzętowego, bez kopii przez procesor
	PathCPU  = "cpu" // kopia klatki do RAM, konwersja w Go, dowolny koder
	PathGDI  = "gdi" // BitBlt; ratunek, gdy DXGI nie działa (sesja RDP, stary sterownik)
)

// Config to parametry silnika. Monitor to indeks z capture.ListDisplays.
type Config struct {
	Monitor int
	FPS     int
	Kbps    int
	Encoder string // preferencja kodera: auto | intel | nvidia | amd | software
	Path    string // PathAuto | PathGPU | PathCPU | PathGDI
	Workers int    // wątki konwersji BGRA→NV12 na ścieżce CPU
}

func (c Config) normalized() Config {
	if c.FPS < minFPS || c.FPS > maxFPS {
		c.FPS = DefaultFPS
	}
	if c.Kbps <= 0 {
		c.Kbps = DefaultKbps
	}
	if c.Encoder == "" {
		c.Encoder = "auto"
	}
	if c.Path == "" {
		c.Path = PathAuto
	}
	if c.Workers <= 0 {
		c.Workers = 4
	}
	return c
}

// Stats to liczniki silnika do audytu i diagnostyki.
type Stats struct {
	Frames     int64
	Bytes      int64
	KeyFrames  int64
	AccessLost int64
	Encoder    string
	Path       string
	Width      int
	Height     int
	FPS        int
	LastError  string
}
