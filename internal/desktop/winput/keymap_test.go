package winput

import "testing"

func TestLookupScan(t *testing.T) {
	cases := []struct {
		code string
		want Scan
	}{
		{"KeyA", Scan{0x1E, false}},
		{"Digit1", Scan{0x02, false}},
		{"Enter", Scan{0x1C, false}},
		{"NumpadEnter", Scan{0x1C, true}}, // ten sam kod co Enter, różni je prefiks E0
		{"ArrowUp", Scan{0x48, true}},
		{"Numpad8", Scan{0x48, false}}, // ten sam kod co strzałka w górę bez prefiksu
		{"ControlRight", Scan{0x1D, true}},
		{"MetaLeft", Scan{0x5B, true}},
		{"F12", Scan{0x58, false}},
	}
	for _, c := range cases {
		got, ok := LookupScan(c.code)
		if !ok || got != c.want {
			t.Errorf("%s: %+v ok=%v, oczekiwano %+v", c.code, got, ok, c.want)
		}
	}
	if _, ok := LookupScan("Nieistniejacy"); ok {
		t.Error("nieznany klawisz nie powinien być znaleziony")
	}
}

func TestScanTableHasNoDuplicateCodes(t *testing.T) {
	seen := map[Scan]string{}
	for code, s := range scanByCode {
		if prev, dup := seen[s]; dup {
			t.Errorf("%s i %s mają ten sam kod skanowania %+v", code, prev, s)
		}
		seen[s] = code
	}
}

func TestAbsCoord(t *testing.T) {
	// Pulpit 1920 px od x=0: skrajne piksele mapują się do początku i końca zakresu 0..65535.
	if got := AbsCoord(0, 0, 1920); got < 0 || got > 40 {
		t.Errorf("pierwszy piksel: %d", got)
	}
	if got := AbsCoord(1919, 0, 1920); got < 65490 || got > 65535 {
		t.Errorf("ostatni piksel: %d", got)
	}
	// Poza zakresem: obcięcie, nie przepełnienie.
	if got := AbsCoord(5000, 0, 1920); got > 65535 {
		t.Errorf("poza zakresem: %d", got)
	}
	if got := AbsCoord(-50, 0, 1920); got < 0 {
		t.Errorf("ujemny: %d", got)
	}
	// Monitor po lewej stronie głównego (początek pulpitu wirtualnego -1920).
	if got := AbsCoord(-1920, -1920, 5760); got > 20 {
		t.Errorf("lewa krawędź pulpitu wirtualnego: %d", got)
	}
	// Monotoniczność i odwrotność: współrzędna bezwzględna wraca do tego samego piksela (system liczy abs*size/65536).
	prev := -1
	for px := 0; px < 1920; px++ {
		a := AbsCoord(px, 0, 1920)
		if a < prev {
			t.Fatalf("brak monotoniczności przy %d", px)
		}
		prev = a
		if back := a * 1920 / 65536; back != px {
			t.Fatalf("piksel %d wraca jako %d", px, back)
		}
	}
	if AbsCoord(10, 0, 1) != 0 {
		t.Error("rozmiar 1 powinien dać 0")
	}
}

func TestNormToPixel(t *testing.T) {
	if got := NormToPixel(0, 100, 1920); got != 100 {
		t.Errorf("0 -> %d", got)
	}
	if got := NormToPixel(1, 100, 1920); got != 100+1919 {
		t.Errorf("1 -> %d", got)
	}
	if got := NormToPixel(0.5, 0, 1920); got != 960 {
		t.Errorf("0.5 -> %d", got)
	}
	if got := NormToPixel(-3, 0, 1920); got != 0 {
		t.Errorf("-3 -> %d", got)
	}
	if got := NormToPixel(9, 0, 1920); got != 1919 {
		t.Errorf("9 -> %d", got)
	}
}
