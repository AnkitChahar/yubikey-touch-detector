//go:build linux

package detector

// NewDetectorStrategy returns the Linux detector strategy, which uses inotify for GPG
// file watching and Linux hidraw devices for U2F and HMAC detection.
func NewDetectorStrategy() DetectorStrategy {
	return DetectorStrategy{
		WatchGPG:  WatchGPGLinux,
		WatchU2F:  WatchU2FLinux,
		WatchHMAC: WatchHMACLinux,
	}
}
