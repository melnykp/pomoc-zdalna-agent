package metrics

import "testing"

func TestCPUPercent(t *testing.T) {
	cases := []struct {
		name      string
		prev, cur cpuTimes
		want      float64
	}{
		{"połowa bezczynności", cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 150, total: 300}, 50},
		{"pełne obciążenie", cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 100, total: 300}, 100},
		{"pełna bezczynność", cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 200, total: 300}, 0},
		{"licznik stoi", cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 100, total: 200}, 0},
		{"licznik cofnięty", cpuTimes{idle: 100, total: 200}, cpuTimes{idle: 50, total: 150}, 0},
		{"zaokrąglenie do 0,1", cpuTimes{idle: 0, total: 0}, cpuTimes{idle: 2, total: 3}, 33.3},
	}
	for _, c := range cases {
		if got := cpuPercent(c.prev, c.cur); got != c.want {
			t.Errorf("%s: %v, oczekiwano %v", c.name, got, c.want)
		}
	}
}

func TestSampleStaysInRange(t *testing.T) {
	s := NewSampler()
	snap := s.Sample()
	if snap.CPUPct < 0 || snap.CPUPct > 100 {
		t.Fatalf("CPU poza zakresem: %v", snap.CPUPct)
	}
	if snap.MemTotalMB < 0 || snap.MemUsedMB < 0 || snap.MemUsedMB > snap.MemTotalMB {
		t.Fatalf("pamięć niespójna: %+v", snap)
	}
	if snap.UptimeS < 0 {
		t.Fatalf("ujemny czas działania: %d", snap.UptimeS)
	}
}
