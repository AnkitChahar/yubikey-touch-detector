//go:build darwin

package detector

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

// WatchHMAC is a stub; HMAC detection on macOS requires IOKit (not yet implemented).
func WatchHMAC(notifiers *sync.Map) {
	log.Debug("HMAC touch detection is not yet supported on macOS; skipping")
}
