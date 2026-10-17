//go:build !windows

package config

// programDataDir poza Windows nie jest używany (katalog danych to /var/lib/<nazwa>).
func programDataDir() string { return "" }
