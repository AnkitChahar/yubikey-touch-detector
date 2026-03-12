//go:build darwin

package detector

import (
	"sync"
	"time"

	hid "github.com/karalabe/hid"
	log "github.com/sirupsen/logrus"
)

// WatchU2FDarwin watches for U2F/FIDO2 touch events on macOS using hidapi (IOKit).
//
// NOTE: macOS 10.15+ restricts unprivileged access to FIDO HID devices. If touch
// detection does not work, run the binary with sudo, or grant Input Monitoring
// permission in System Settings → Privacy & Security → Input Monitoring.
func WatchU2FDarwin(notifiers *sync.Map) {
	// Poll for new FIDO devices every second. hidapi has no hotplug callback on macOS.
	known := map[string]bool{}

	for {
		devices := hid.Enumerate(0, 0) // enumerate all HID devices
		for _, info := range devices {
			if info.UsagePage != FIDO_USAGE_PAGE || info.Usage != FIDO_USAGE_U2F {
				continue
			}
			if known[info.Path] {
				continue
			}
			known[info.Path] = true
			log.Debugf("U2F Darwin: found FIDO device at %v (vendor=%04x product=%04x)", info.Path, info.VendorID, info.ProductID)

			dev, err := info.Open()
			if err != nil {
				// Keep in known so we don't retry every second. The device will be
				// re-attempted when it is physically reconnected (new path).
				// Common cause: macOS restricts FIDO HID access without Input Monitoring
				// permission (System Settings → Privacy & Security → Input Monitoring).
				log.Warnf("U2F Darwin: cannot open FIDO device %v: %v (grant Input Monitoring permission if needed)", info.Path, err)
				continue
			}
			go runU2FPacketWatcher(dev, notifiers)
		}
		time.Sleep(1 * time.Second)
	}
}
