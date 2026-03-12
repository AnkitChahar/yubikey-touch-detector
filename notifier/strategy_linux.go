//go:build linux

package notifier

import "sync"

// SetupPlatformNotifier sets up the Linux desktop notification backend (libnotify).
// On Linux this is invoked when the user passes --notify (or --libnotify for backwards compat).
func SetupPlatformNotifier(notifiers *sync.Map) {
	SetupLibnotifyNotifier(notifiers)
}
