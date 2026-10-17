// Package heartbeat składa wiadomość hb z metryk maszyny (docs/ARCHITECTURE.md).
package heartbeat

import (
	"net"

	"github.com/melnykp/pomoc-zdalna-agent/internal/metrics"
	"github.com/melnykp/pomoc-zdalna-agent/pkg/wire"
)

// Collector składa kolejne heartbeaty.
type Collector struct {
	sampler  *metrics.Sampler
	versions wire.Versions
}

// New tworzy kolektor z wersjami komponentów do raportowania.
func New(versions wire.Versions) *Collector {
	return &Collector{sampler: metrics.NewSampler(), versions: versions}
}

// SetVersions podmienia raportowane wersje (np. po aktualizacji modułu).
func (c *Collector) SetVersions(v wire.Versions) { c.versions = v }

// Collect zwraca aktualny heartbeat.
func (c *Collector) Collect() wire.Heartbeat {
	s := c.sampler.Sample()
	return wire.Heartbeat{
		CPUPct:     s.CPUPct,
		MemUsedMB:  s.MemUsedMB,
		MemTotalMB: s.MemTotalMB,
		UptimeS:    s.UptimeS,
		LoggedUser: s.LoggedUser,
		IPLocal:    localIPs(),
		Versions:   c.versions,
	}
}

// localIPs zwraca adresy interfejsów poza loopbackiem i link-local, nie więcej niż serwer przyjmie (16).
func localIPs() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return []string{}
	}
	out := []string{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if len(out) == 16 {
			break
		}
		out = append(out, ipn.IP.String())
	}
	return out
}
