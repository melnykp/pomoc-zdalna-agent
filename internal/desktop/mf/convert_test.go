package mf

import (
	"bytes"
	"math/rand"
	"testing"
)

// bgra buduje jednolity obraz BGRA w x h z paddingiem wiersza (stride > w*4), by sprawdzić obsługę stride.
func bgra(w, h, stride int, r, g, b byte) []byte {
	pix := make([]byte, stride*h)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			o := y*stride + x*4
			pix[o], pix[o+1], pix[o+2], pix[o+3] = b, g, r, 255
		}
	}
	return pix
}

func near(a, b byte, tol int) bool {
	d := int(a) - int(b)
	return d >= -tol && d <= tol
}

func TestBGRAToNV12KnownColors(t *testing.T) {
	// Wartości odniesienia BT.709, zakres ograniczony.
	cases := []struct {
		name    string
		r, g, b byte
		y, u, v byte
	}{
		{"czarny", 0, 0, 0, 16, 128, 128},
		{"biały", 255, 255, 255, 235, 128, 128},
		{"czerwony", 255, 0, 0, 63, 102, 240},
		{"zielony", 0, 255, 0, 173, 42, 26},
		{"niebieski", 0, 0, 255, 32, 240, 118},
	}
	const w, h, stride = 8, 6, 8*4 + 16
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst := make([]byte, w*h*3/2)
			BGRAToNV12(dst, w, h, bgra(w, h, stride, c.r, c.g, c.b), stride, 1)
			for i := 0; i < w*h; i++ {
				if !near(dst[i], c.y, 1) {
					t.Fatalf("Y[%d]=%d, oczekiwano %d", i, dst[i], c.y)
				}
			}
			for i := 0; i < w*h/2; i += 2 {
				if !near(dst[w*h+i], c.u, 1) || !near(dst[w*h+i+1], c.v, 1) {
					t.Fatalf("UV[%d]=(%d,%d), oczekiwano (%d,%d)", i, dst[w*h+i], dst[w*h+i+1], c.u, c.v)
				}
			}
		})
	}
}

func TestBGRAToNV12ParallelEqualsSerial(t *testing.T) {
	const w, h, stride = 64, 38, 64*4 + 32
	rng := rand.New(rand.NewSource(1))
	src := make([]byte, stride*h)
	rng.Read(src)
	a := make([]byte, w*h*3/2)
	b := make([]byte, w*h*3/2)
	BGRAToNV12(a, w, h, src, stride, 1)
	for _, workers := range []int{2, 3, 4, 7, 64} {
		for i := range b {
			b[i] = 0
		}
		BGRAToNV12(b, w, h, src, stride, workers)
		if !bytes.Equal(a, b) {
			t.Fatalf("wynik równoległy (%d wątków) różni się od szeregowego", workers)
		}
	}
}

func TestBGRAToNV12CropIgnoresRest(t *testing.T) {
	// Kodujemy wycinek 4x4 z obrazu o szerszym stride; piksele poza wycinkiem nie mogą wpływać na wynik.
	const w, h, stride = 4, 4, 64
	src := bgra(16, 8, stride, 255, 0, 0)
	dst := make([]byte, w*h*3/2)
	BGRAToNV12(dst, w, h, src, stride, 2)
	for i := 0; i < w*h; i++ {
		if !near(dst[i], 63, 1) {
			t.Fatalf("Y[%d]=%d", i, dst[i])
		}
	}
}

func TestSplitAnnexB(t *testing.T) {
	// SPS(7) z 4-bajtowym kodem startowym, PPS(8) z 3-bajtowym, IDR(5) z końcowymi zerami.
	stream := []byte{
		0, 0, 0, 1, 0x67, 1, 2, 3,
		0, 0, 1, 0x68, 4, 5,
		0, 0, 0, 1, 0x65, 9, 9, 9, 0, 0,
	}
	nals := SplitAnnexB(stream)
	if len(nals) != 3 {
		t.Fatalf("jednostek NAL: %d, oczekiwano 3", len(nals))
	}
	wantTypes := []byte{7, 8, 5}
	for i, n := range nals {
		if n.Type != wantTypes[i] {
			t.Errorf("NAL %d: typ %d, oczekiwano %d", i, n.Type, wantTypes[i])
		}
	}
	if !bytes.Equal(nals[2].Data, []byte{0x65, 9, 9, 9}) {
		t.Errorf("końcowe zera nie zostały obcięte: % x", nals[2].Data)
	}
	if got := SplitAnnexB(nil); len(got) != 0 {
		t.Errorf("pusty strumień dał %d jednostek", len(got))
	}
	if got := SplitAnnexB([]byte{1, 2, 3, 4}); len(got) != 0 {
		t.Errorf("strumień bez kodu startowego dał %d jednostek", len(got))
	}
}
