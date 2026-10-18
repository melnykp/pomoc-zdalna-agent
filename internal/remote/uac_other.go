//go:build !windows

package remote

// uacDisabled poza Windows nie ma sensu (silnik pulpitu działa tylko w Windows).
func uacDisabled() bool { return false }
