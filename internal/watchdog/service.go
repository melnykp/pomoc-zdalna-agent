package watchdog

import (
	"context"
	"net"
	"net/url"
	"time"

	"github.com/melnykp/pomoc-zdalna-agent/internal/svc"
)

// ServiceController steruje agentem przez menedżera usług Windows.
type ServiceController struct{ Name string }

// Stop zatrzymuje usługę i czeka na stan Stopped.
func (c ServiceController) Stop(context.Context) error { return svc.Stop(c.Name) }

// Start uruchamia usługę i czeka na stan Running.
func (c ServiceController) Start(context.Context) error { return svc.Start(c.Name) }

// Running mówi, czy usługa działa.
func (c ServiceController) Running() bool { return svc.IsRunning(c.Name) }

// Reachable zwraca funkcję sprawdzającą, czy komputer dosięga serwera: zwykłe połączenie TCP z hostem z adresu
// bramki, bez uwierzytelniania i bez wysyłania danych.
func Reachable(serverURL string) func(ctx context.Context) bool {
	return func(ctx context.Context) bool {
		u, err := url.Parse(serverURL)
		if err != nil || u.Host == "" {
			return false
		}
		host := u.Host
		if u.Port() == "" {
			if u.Scheme == "http" {
				host = net.JoinHostPort(u.Hostname(), "80")
			} else {
				host = net.JoinHostPort(u.Hostname(), "443")
			}
		}
		d := net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}
}
