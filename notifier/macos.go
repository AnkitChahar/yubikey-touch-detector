//go:build darwin

package notifier

import (
	"os/exec"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// SetupMacOSNotifier sends macOS system notifications via osascript when
// a YubiKey touch is required. It aggregates concurrent touch events so only
// one notification is shown while any touch wait is active.
func SetupMacOSNotifier(notifiers *sync.Map) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/macos", touch)

	var activeTouchWaits int32

	for msg := range touch {
		switch msg {
		case GPG_ON, U2F_ON, HMAC_ON:
			if atomic.AddInt32(&activeTouchWaits, 1) == 1 {
				log.Infof("macOS notifier: sending notification for %v", msg)
				sendMacOSNotification("Touch your YubiKey now", "YubiKey touch required")
			}
			log.Debugf("macOS notifier: touch wait started (%v active)", atomic.LoadInt32(&activeTouchWaits))

		case GPG_OFF, U2F_OFF, HMAC_OFF:
			remaining := atomic.AddInt32(&activeTouchWaits, -1)
			if remaining < 0 {
				// Guard against mismatched ON/OFF pairs.
				atomic.StoreInt32(&activeTouchWaits, 0)
			}
			log.Debugf("macOS notifier: touch wait ended (%v remaining)", atomic.LoadInt32(&activeTouchWaits))
		}
	}
}

func sendMacOSNotification(message, title string) {
	imagePath := "/usr/local/share/yubikey-touch-detector/yubikey-touch-detector.png"
	script := `display notification "` + message + `" with title "` + title + `" sound name "Ping" image from file "` + imagePath + `"`
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		log.Warnf("macOS notifier: osascript failed: %v", err)
	}
}
