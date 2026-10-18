package mf

import "sync"

// BGRAToNV12 zamienia obraz BGRA (4 bajty na piksel, kolejność B,G,R,A) na NV12 (płaszczyzna Y, potem przeplecione UV),
// macierz BT.709, zakres ograniczony (16–235). Szerokość i wysokość muszą być parzyste. dst ma mieć w*h*3/2 bajtów.
// workers>1 dzieli pracę na pasy wierszy.
func BGRAToNV12(dst []byte, w, h int, src []byte, stride int, workers int) {
	if workers < 1 {
		workers = 1
	}
	pairs := h / 2
	if workers > pairs {
		workers = pairs
	}
	yPlane := dst[:w*h]
	uvPlane := dst[w*h : w*h+w*h/2]
	if workers == 1 {
		convertRows(yPlane, uvPlane, w, src, stride, 0, pairs)
		return
	}
	var wg sync.WaitGroup
	per := (pairs + workers - 1) / workers
	for s := 0; s < pairs; s += per {
		e := s + per
		if e > pairs {
			e = pairs
		}
		wg.Add(1)
		go func(s, e int) {
			defer wg.Done()
			convertRows(yPlane, uvPlane, w, src, stride, s, e)
		}(s, e)
	}
	wg.Wait()
}

// convertRows przelicza pary wierszy [from,to).
func convertRows(yPlane, uvPlane []byte, w int, src []byte, stride, from, to int) {
	for p := from; p < to; p++ {
		y0 := 2 * p
		r0 := src[y0*stride : y0*stride+w*4]
		r1 := src[(y0+1)*stride : (y0+1)*stride+w*4]
		yr0 := yPlane[y0*w : y0*w+w]
		yr1 := yPlane[(y0+1)*w : (y0+1)*w+w]
		uv := uvPlane[p*w : p*w+w]
		for x := 0; x < w; x += 2 {
			i := x * 4
			b00, g00, r00 := int32(r0[i]), int32(r0[i+1]), int32(r0[i+2])
			b01, g01, r01 := int32(r0[i+4]), int32(r0[i+5]), int32(r0[i+6])
			b10, g10, r10 := int32(r1[i]), int32(r1[i+1]), int32(r1[i+2])
			b11, g11, r11 := int32(r1[i+4]), int32(r1[i+5]), int32(r1[i+6])
			yr0[x] = byte((47*r00+157*g00+16*b00+128)>>8 + 16)
			yr0[x+1] = byte((47*r01+157*g01+16*b01+128)>>8 + 16)
			yr1[x] = byte((47*r10+157*g10+16*b10+128)>>8 + 16)
			yr1[x+1] = byte((47*r11+157*g11+16*b11+128)>>8 + 16)
			r := (r00 + r01 + r10 + r11 + 2) >> 2
			g := (g00 + g01 + g10 + g11 + 2) >> 2
			b := (b00 + b01 + b10 + b11 + 2) >> 2
			uv[x] = byte((-26*r-87*g+112*b+128)>>8 + 128)
			uv[x+1] = byte((112*r-102*g-10*b+128)>>8 + 128)
		}
	}
}

// NALUnit to jednostka strumienia H.264 (bez kodu startowego).
type NALUnit struct {
	Type byte
	Data []byte
}

// SplitAnnexB rozbija strumień Annex B (kody startowe 00 00 01 / 00 00 00 01) na jednostki NAL.
func SplitAnnexB(b []byte) []NALUnit {
	var out []NALUnit
	n := len(b)
	start := -1
	i := 0
	for i+3 <= n {
		if b[i] == 0 && b[i+1] == 0 && b[i+2] == 1 {
			if start >= 0 {
				end := i
				for end > start && b[end-1] == 0 {
					end--
				}
				if end > start {
					out = append(out, NALUnit{Type: b[start] & 0x1f, Data: b[start:end]})
				}
			}
			start = i + 3
			i += 3
			continue
		}
		i++
	}
	if start >= 0 && start < n {
		end := n
		for end > start && b[end-1] == 0 { // końcowe zera to wypełnienie, nie część jednostki
			end--
		}
		if end > start {
			out = append(out, NALUnit{Type: b[start] & 0x1f, Data: b[start:end]})
		}
	}
	return out
}
