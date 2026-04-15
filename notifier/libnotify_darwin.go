//go:build darwin

package notifier

import (
	"os/exec"
	"sync"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// SetupLibnotifyNotifier sends macOS system notifications via osascript when
// a YubiKey touch is required. Unlike the Linux implementation it cannot
// auto-dismiss the notification banner when the touch is confirmed, as macOS
// provides no API for that via osascript.
func SetupLibnotifyNotifier(notifiers *sync.Map) {
	touch := make(chan Message, 10)
	notifiers.Store("notifier/libnotify", touch)

	var activeTouchWaits int32

	for msg := range touch {
		switch msg {
		case GPG_ON, U2F_ON, HMAC_ON:
			if atomic.AddInt32(&activeTouchWaits, 1) == 1 {
				go sendMacOSNotification()
			}
		case GPG_OFF, U2F_OFF, HMAC_OFF:
			if remaining := atomic.AddInt32(&activeTouchWaits, -1); remaining < 0 {
				atomic.StoreInt32(&activeTouchWaits, 0)
			}
		}
	}
}

func sendMacOSNotification() {
	script := `display notification "YubiKey is waiting for a touch" with title "YubiKey touch detector"`
	if err := exec.Command("osascript", "-e", script).Run(); err != nil {
		log.Warnf("macOS notifier: osascript failed: %v", err)
	}
}
