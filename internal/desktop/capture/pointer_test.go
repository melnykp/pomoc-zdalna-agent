//go:build windows

package capture

import (
	"image/color"
	"testing"
)

func TestDecodePointerShapeColorKeepsAlphaAndSwapsBGRA(t *testing.T) {
	// 2x1 BGRA: piksel 1 czerwony kryjący, piksel 2 niebieski półprzezroczysty.
	raw := []byte{0, 0, 255, 255, 255, 0, 0, 128}
	img := decodePointerShape(pointerShapeInfo{Type: pointerColor, Width: 2, Height: 1, Pitch: 8, HotX: 1}, raw)
	if img == nil {
		t.Fatal("brak obrazu")
	}
	if got := img.NRGBAAt(0, 0); got != (color.NRGBA{R: 255, A: 255}) {
		t.Fatalf("piksel 0: %+v", got)
	}
	if got := img.NRGBAAt(1, 0); got != (color.NRGBA{B: 255, A: 128}) {
		t.Fatalf("piksel 1: %+v", got)
	}
}

func TestDecodePointerShapeMonochromeMasks(t *testing.T) {
	// 8x1 (wysokość 2 w surowych danych): AND = 1100 0000, XOR = 0100 0000.
	// x0: AND=1,XOR=0 przezroczysty; x1: AND=1,XOR=1 odwrócenie; x2: AND=0,XOR=0 czarny; reszta czarna.
	raw := []byte{0xC0, 0x40}
	img := decodePointerShape(pointerShapeInfo{Type: pointerMonochrome, Width: 8, Height: 2, Pitch: 1}, raw)
	if img == nil {
		t.Fatal("brak obrazu")
	}
	if img.Bounds().Dy() != 1 {
		t.Fatalf("wysokość obrazu %d, oczekiwano 1", img.Bounds().Dy())
	}
	if a := img.NRGBAAt(0, 0).A; a != 0 {
		t.Fatalf("x0 powinien być przezroczysty, alfa=%d", a)
	}
	if got := img.NRGBAAt(1, 0); got.A == 0 || got.A == 255 {
		t.Fatalf("x1 (odwrócenie) powinien być półprzezroczysty: %+v", got)
	}
	if got := img.NRGBAAt(2, 0); got != (color.NRGBA{A: 255}) {
		t.Fatalf("x2 powinien być czarny: %+v", got)
	}
}

func TestDecodePointerShapeRejectsGarbage(t *testing.T) {
	if decodePointerShape(pointerShapeInfo{Type: pointerColor, Width: 4, Height: 4, Pitch: 16}, make([]byte, 10)) != nil {
		t.Fatal("za krótkie dane powinny dać nil")
	}
	if decodePointerShape(pointerShapeInfo{Type: 9, Width: 4, Height: 4, Pitch: 16}, make([]byte, 64)) != nil {
		t.Fatal("nieznany typ powinien dać nil")
	}
	if decodePointerShape(pointerShapeInfo{Type: pointerColor, Width: 4096, Height: 4, Pitch: 16384}, make([]byte, 65536)) != nil {
		t.Fatal("absurdalny rozmiar powinien dać nil")
	}
}
