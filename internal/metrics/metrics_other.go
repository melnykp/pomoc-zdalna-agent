//go:build !windows && !linux

package metrics

func readCPU() (cpuTimes, bool)           { return cpuTimes{}, false }
func readMemory() (usedMB, totalMB int64) { return 0, 0 }
func readUptime() int64                   { return 0 }
func readLoggedUser() string              { return "" }
