//go:build darwin

package notifier

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

func SetupLibnotifyNotifier(_ *sync.Map) {
	log.Warn("libnotify is not supported on macOS")
}
