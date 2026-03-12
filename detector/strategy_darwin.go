//go:build darwin

package detector

// NewDetectorStrategy returns the macOS detector strategy, which uses a gpg-agent
// socket proxy for GPG detection and IOKit HID for U2F detection.
func NewDetectorStrategy() DetectorStrategy {
	return DetectorStrategy{
		WatchGPG:  WatchGPGDarwin,
		WatchU2F:  WatchU2FDarwin,
		WatchHMAC: WatchHMACDarwin,
	}
}
