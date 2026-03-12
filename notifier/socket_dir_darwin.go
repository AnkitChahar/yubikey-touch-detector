//go:build darwin

package notifier

import (
	"os"
)

func socketRuntimeDir() string {
	// macOS does not have XDG_RUNTIME_DIR; fall back to $TMPDIR (guaranteed on macOS).
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return dir
	}
	if dir := os.Getenv("TMPDIR"); dir != "" {
		return dir
	}
	return "/tmp"
}
