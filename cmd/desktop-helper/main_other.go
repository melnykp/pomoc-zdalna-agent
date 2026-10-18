//go:build !windows

// desktop-helper działa tylko w Windows; poza nim plik buduje się jako pusty program, żeby `go vet ./...` przechodził w CI.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "desktop-helper działa tylko w Windows")
	os.Exit(2)
}
