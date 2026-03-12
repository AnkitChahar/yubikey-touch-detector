//go:build darwin

package notifier

import "sync"

// SetupPlatformNotifier sets up the macOS desktop notification backend (osascript).
// On macOS this is enabled by default when --notify is passed.
func SetupPlatformNotifier(notifiers *sync.Map) {
	SetupMacOSNotifier(notifiers)
}
