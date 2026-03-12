//go:build darwin

package detector

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// WatchHMACDarwin is a stub for HMAC-challenge touch detection on macOS.
// The Linux implementation relies on Linux-specific sysfs paths (/sys/class/hidraw)
// that do not exist on macOS. A full IOKit-based implementation is a future TODO.
func WatchHMACDarwin(notifiers *sync.Map) {
	log.Debug("HMAC touch detection is not yet supported on macOS; skipping")
}
