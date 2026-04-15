//go:build darwin

package notifier

import (
	"os"
)

func socketRuntimeDir() string {
	if dir := os.Getenv("TMPDIR"); dir != "" {
		return dir
	}
	return "/tmp"
}
