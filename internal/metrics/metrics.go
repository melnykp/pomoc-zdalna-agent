// Package metrics zbiera stan maszyny do heartbeatu (docs/ARCHITECTURE.md): CPU, pamięć, czas
// działania i zalogowanego użytkownika. Bez zewnętrznych bibliotek: Windows przez x/sys, Linux przez /proc.
package metrics

import "sync"

// Snapshot to pojedynczy odczyt.
type Snapshot struct {
	CPUPct     float64
	MemUsedMB  int64
	MemTotalMB int64
	UptimeS    int64
	LoggedUser string
}

// cpuTimes to skumulowane liczniki czasu procesora w dowolnej jednostce.
type cpuTimes struct{ idle, total uint64 }

// cpuPercent liczy obciążenie z różnicy dwóch odczytów. Brak postępu licznika daje 0.
func cpuPercent(prev, cur cpuTimes) float64 {
	if cur.total <= prev.total || cur.idle < prev.idle {
		return 0
	}
	total := float64(cur.total - prev.total)
	idle := float64(cur.idle - prev.idle)
	pct := 100 * (1 - idle/total)
	switch {
	case pct < 0:
		return 0
	case pct > 100:
		return 100
	}
	return float64(int(pct*10+0.5)) / 10
}

// Sampler pamięta poprzedni odczyt CPU, żeby liczyć obciążenie między heartbeatami.
type Sampler struct {
	mu   sync.Mutex
	prev cpuTimes
	have bool
}

// NewSampler tworzy próbnik i od razu zapisuje odczyt bazowy.
func NewSampler() *Sampler {
	s := &Sampler{}
	if c, ok := readCPU(); ok {
		s.prev, s.have = c, true
	}
	return s
}

// Sample zwraca bieżący odczyt.
func (s *Sampler) Sample() Snapshot {
	snap := Snapshot{}
	s.mu.Lock()
	if c, ok := readCPU(); ok {
		if s.have {
			snap.CPUPct = cpuPercent(s.prev, c)
		}
		s.prev, s.have = c, true
	}
	s.mu.Unlock()
	snap.MemUsedMB, snap.MemTotalMB = readMemory()
	snap.UptimeS = readUptime()
	snap.LoggedUser = readLoggedUser()
	return snap
}
