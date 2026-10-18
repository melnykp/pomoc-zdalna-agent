//go:build windows

package capture

import (
	"runtime"
	"testing"
)

var procLoadCursorW = user32.NewProc("LoadCursorW")

const idcArrow = 32512

func TestRenderCursorShapeRecoversAlphaFromBlackAndWhiteBackgrounds(t *testing.T) {
	h, _, _ := procLoadCursorW.Call(0, idcArrow)
	if h == 0 {
		t.Skip("brak standardowego kursora systemowego")
	}
	shape := renderCursorShape(h)
	if shape == nil || shape.Image == nil {
		t.Fatal("brak kształtu kursora strzałki")
	}
	b := shape.Image.Bounds()
	if b.Dx() < 8 || b.Dy() < 8 || b.Dx() > maxCursorSide {
		t.Fatalf("rozmiar kursora %dx%d", b.Dx(), b.Dy())
	}
	var opaque, transparent int
	for y := 0; y < b.Dy(); y++ {
		for x := 0; x < b.Dx(); x++ {
			switch a := shape.Image.NRGBAAt(x, y).A; {
			case a == 255:
				opaque++
			case a == 0:
				transparent++
			}
		}
	}
	// Strzałka ma pełne piksele (wnętrze i obrys) i przezroczyste tło; same piksele kryjące albo same przezroczyste to błąd odzysku alfa.
	if opaque < 20 || transparent < 100 {
		t.Fatalf("piksele kryjące %d, przezroczyste %d", opaque, transparent)
	}
	// Strzałka ma punkt zaczepienia w lewym górnym rogu.
	if shape.HotX > 4 || shape.HotY > 4 {
		t.Fatalf("punkt zaczepienia strzałki (%d,%d)", shape.HotX, shape.HotY)
	}
}

func TestAlphaFromBackgroundsMath(t *testing.T) {
	// 3 piksele (BGRA): kryjący czerwony, półprzezroczysty biały (alfa ~50%), w pełni przezroczysty.
	onBlack := []byte{0, 0, 255, 255, 128, 128, 128, 255, 0, 0, 0, 255}
	onWhite := []byte{0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
	img := alphaFromBackgrounds(onBlack, onWhite, 3, 1)
	if c := img.NRGBAAt(0, 0); c.R != 255 || c.G != 0 || c.B != 0 || c.A != 255 {
		t.Fatalf("kryjący czerwony: %+v", c)
	}
	if c := img.NRGBAAt(1, 0); c.A < 120 || c.A > 135 || c.R < 250 {
		t.Fatalf("półprzezroczysty biały: %+v", c)
	}
	if c := img.NRGBAAt(2, 0); c.A != 0 {
		t.Fatalf("przezroczysty: %+v", c)
	}
}

func TestCursorTrackerReportsShapeOnlyOnHandleChange(t *testing.T) {
	var c cursorTracker
	c.have = true
	c.last = Pointer{X: 10, Y: 20, Visible: true}
	c.handle = 1
	// Bez zmian: nic do wysłania.
	if _, ok := c.take(); ok {
		t.Fatal("bez zmian nie ma czego wysyłać")
	}
	// Ruch: pełny stan, bez kształtu.
	c.last.X = 30
	c.pending.Moved = true
	p, ok := c.take()
	if !ok || p.X != 30 || p.Y != 20 || !p.Visible || p.Shape != nil {
		t.Fatalf("ruch: %+v ok=%v", p, ok)
	}
	if _, ok := c.take(); ok {
		t.Fatal("po odbiorze zmiany znikają")
	}
}

func TestGDIGrabReturnsFullFrameAndPointerFromThisDesktop(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var td ThreadDesktop
	defer td.Close()
	if _, err := td.Attach(); err != nil {
		t.Skipf("brak pulpitu wejściowego (sesja zablokowana?): %v", err)
	}
	g, err := OpenGDI(0, 0, 320, 200)
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	f, err := g.Grab(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.Width != 320 || f.Height != 200 || f.Stride != 320*4 || len(f.Pix) != 320*200*4 {
		t.Fatalf("klatka: %dx%d stride %d len %d", f.Width, f.Height, f.Stride, len(f.Pix))
	}
	// Druga klatka tym samym źródłem (DC pobierany od nowa przy każdej klatce) też działa.
	if _, err := g.Grab(0, f.Pix); err != nil {
		t.Fatal(err)
	}
	// Kursor jest raportowany przynajmniej raz (położenie), a gdy jest widoczny, także jego kształt.
	p, ok := g.Pointer()
	if !ok {
		t.Fatal("pierwszy odczyt kursora powinien coś zwrócić")
	}
	if p.Visible && p.Shape == nil {
		t.Fatal("widoczny kursor bez kształtu")
	}
}

func TestThreadDesktopAttachNamesInputDesktop(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var td ThreadDesktop
	defer td.Close()
	name, err := td.Attach()
	if err != nil {
		t.Skipf("nie można dołączyć do pulpitu wejściowego: %v", err)
	}
	if name == "" {
		t.Fatal("nazwa pulpitu wejściowego pusta")
	}
	// Drugie dołączenie (jak przed każdą próbą otwarcia) jest bezpieczne i zwalnia poprzedni uchwyt.
	if n2, err := td.Attach(); err != nil || n2 != name {
		t.Fatalf("ponowne dołączenie: %q %v", n2, err)
	}
}
