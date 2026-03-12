package detector

import "sync"

// DetectorStrategy holds platform-specific detector implementations as first-class functions.
// Use NewDetectorStrategy() to obtain the correct implementation for the current OS.
type DetectorStrategy struct {
	// WatchGPG triggers requestGPGCheck whenever a GPG key access is detected.
	// filesToWatch is the set of shadowed private key files (used on Linux); Darwin
	// implementations may ignore this and use a socket proxy instead.
	// exits is used by implementations that hold resources (e.g. socket proxies) so
	// they can clean up on graceful shutdown.
	WatchGPG func(filesToWatch []string, requestGPGCheck chan bool, exits *sync.Map)

	// WatchU2F monitors U2F/FIDO2 HID traffic and emits U2F_ON / U2F_OFF to notifiers.
	WatchU2F func(notifiers *sync.Map)

	// WatchHMAC monitors HMAC-challenge traffic and emits HMAC_ON / HMAC_OFF to notifiers.
	WatchHMAC func(notifiers *sync.Map)
}
