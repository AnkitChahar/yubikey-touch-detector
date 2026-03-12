//go:build linux

package notifier

import (
	"os"

	log "github.com/sirupsen/logrus"
)

func socketRuntimeDir() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		log.Error("Cannot setup unix socket notifier, $XDG_RUNTIME_DIR is not defined.")
	}
	return dir
}
