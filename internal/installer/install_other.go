//go:build !windows

package installer

import (
	"context"
	"errors"
)

// ErrUnsupported oznacza instalację dostępną tylko w Windows.
var ErrUnsupported = errors.New("instalacja usługi jest dostępna tylko w systemie Windows")

// Install poza Windows tylko rejestruje urządzenie (tryb rozwojowy); usługi nie zakłada.
func Install(ctx context.Context, p Params) (Result, error) { return Enroll(ctx, p) }

// Retire poza Windows nie robi nic.
func Retire() error { return ErrUnsupported }

// Uninstall poza Windows nie robi nic.
func Uninstall() error { return ErrUnsupported }
