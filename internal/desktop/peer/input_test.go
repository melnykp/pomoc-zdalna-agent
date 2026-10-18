package peer

import (
	"errors"
	"reflect"
	"testing"
)

type fakeInjector struct {
	log  []string
	fail bool
}

func (f *fakeInjector) Move(x, y float64) error { f.log = append(f.log, "mm"); return nil }
func (f *fakeInjector) Button(b int, down bool) error {
	if f.fail {
		return errors.New("odmowa")
	}
	if down {
		f.log = append(f.log, "md"+string(rune('0'+b)))
	} else {
		f.log = append(f.log, "mu"+string(rune('0'+b)))
	}
	return nil
}
func (f *fakeInjector) Wheel(dx, dy int) error { f.log = append(f.log, "wh"); return nil }
func (f *fakeInjector) Key(code string, down bool) error {
	if down {
		f.log = append(f.log, "kd:"+code)
	} else {
		f.log = append(f.log, "ku:"+code)
	}
	return nil
}

func TestReleaseAllLetsGoButtonsThenKeysWithModifiersLast(t *testing.T) {
	inj := &fakeInjector{}
	p := NewPressed()
	for _, m := range []InputMsg{{T: "kd", C: "ControlLeft"}, {T: "kd", C: "KeyA"}, {T: "md", B: 0}, {T: "kd", C: "ShiftLeft"}, {T: "md", B: 2}, {T: "kd", C: "KeyB"}, {T: "ku", C: "KeyB"}} {
		if ok, err := Apply(inj, p, m); !ok || err != nil {
			t.Fatalf("%+v: ok=%v err=%v", m, ok, err)
		}
	}
	if p.Count() != 5 {
		t.Fatalf("wciśniętych %d, oczekiwano 5", p.Count())
	}
	inj.log = nil
	if n := p.ReleaseAll(inj); n != 5 {
		t.Fatalf("puszczono %d", n)
	}
	want := []string{"mu0", "mu2", "ku:KeyA", "ku:ControlLeft", "ku:ShiftLeft"}
	if !reflect.DeepEqual(inj.log, want) {
		t.Fatalf("porządek puszczania: %v", inj.log)
	}
	if p.Count() != 0 || p.ReleaseAll(inj) != 0 {
		t.Fatal("po puszczeniu rejestr powinien być pusty")
	}
}

func TestApplyDoesNotRecordFailedPress(t *testing.T) {
	inj := &fakeInjector{fail: true}
	p := NewPressed()
	if _, err := Apply(inj, p, InputMsg{T: "md", B: 0}); err == nil {
		t.Fatal("oczekiwano błędu")
	}
	if p.Count() != 0 {
		t.Fatal("nieudane wciśnięcie nie może zostać w rejestrze")
	}
}

func TestApplyIgnoresNonInputMessages(t *testing.T) {
	inj := &fakeInjector{}
	for _, tt := range []string{"ping", "cfg", "release", "nieznane"} {
		if ok, err := Apply(inj, NewPressed(), InputMsg{T: tt}); ok || err != nil {
			t.Fatalf("%s: ok=%v err=%v", tt, ok, err)
		}
	}
	if len(inj.log) != 0 {
		t.Fatal("nic nie powinno zostać wstrzyknięte")
	}
}

func TestParseInputRejectsGarbageAndOversize(t *testing.T) {
	if _, ok := ParseInput([]byte(`{"x":1}`)); ok {
		t.Fatal("brak typu powinien zostać odrzucony")
	}
	if _, ok := ParseInput([]byte(`{"t":"kd","c":"` + string(make([]byte, 600)) + `"}`)); ok {
		t.Fatal("za duża ramka powinna zostać odrzucona")
	}
	m, ok := ParseInput([]byte(`{"t":"cfg","mon":1,"fps":60}`))
	if !ok || m.Mon == nil || *m.Mon != 1 || m.FPS == nil || *m.FPS != 60 {
		t.Fatalf("cfg: %+v ok=%v", m, ok)
	}
}
