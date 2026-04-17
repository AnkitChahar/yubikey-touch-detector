//go:build linux

package detector

import (
	"io"
	"sync"
	"time"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

const (
	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f_hid.h
	// and its backwards-compatible successor
	// https://fidoalliance.org/specs/fido2/fido-client-to-authenticator-protocol-v2.1-rd-20191217.html
	TYPE_INIT          = 0x80
	CTAPHID_MSG        = TYPE_INIT | 0x03
	CTAPHID_KEEPALIVE  = TYPE_INIT | 0x3b
	FIDO_USAGE_PAGE    = 0xf1d0
	FIDO_USAGE_CTAPHID = 0x01
	STATUS_UPNEEDED    = 0x02

	// https://fidoalliance.org/specs/u2f-specs-master/inc/u2f.h
	U2F_SW_CONDITIONS_NOT_SATISFIED = 0x6985

	// https://github.com/torvalds/linux/blob/master/include/linux/hid.h
	HID_ITEM_TYPE_GLOBAL           = 1
	HID_ITEM_TYPE_LOCAL            = 2
	HID_GLOBAL_ITEM_TAG_USAGE_PAGE = 0
	HID_LOCAL_ITEM_TAG_USAGE       = 0
)

// runU2FPacketWatcher reads 64-byte CTAPHID packets from a HID device and emits
// U2F_ON / U2F_OFF events to notifiers. The device is closed when the watcher exits.
// This logic is platform-independent; only the device source differs per OS.
func runU2FPacketWatcher(device io.ReadCloser, notifiers *sync.Map) {
	defer device.Close()

	payload := make([]byte, 64)
	lastMessage := notifier.U2F_OFF
	var u2fOffTimer *time.Timer

	for {
		_, err := device.Read(payload)
		if err != nil {
			if u2fOffTimer != nil {
				u2fOffTimer.Stop()
			}
			if lastMessage != notifier.U2F_OFF {
				notifiers.Range(func(_, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_OFF
					return true
				})
			}
			return
		}

		val1b := payload[7]
		val2b := (int(payload[7]) << 8) | int(payload[8])
		isU2F := payload[4] == CTAPHID_MSG && val2b == U2F_SW_CONDITIONS_NOT_SATISFIED
		isFIDO2 := payload[4] == CTAPHID_KEEPALIVE && val1b == STATUS_UPNEEDED

		if u2fOffTimer != nil {
			u2fOffTimer.Stop()
		}

		// Default debounce: device was probably touched, wait a tiny bit for confirmation.
		u2fOffTimerDuration := 200 * time.Millisecond

		if isU2F || isFIDO2 {
			if lastMessage != notifier.U2F_ON {
				notifiers.Range(func(_, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_ON
					return true
				})
				lastMessage = notifier.U2F_ON
			}
			// Still waiting for touch — extend the off-timer.
			u2fOffTimerDuration = 2 * time.Second
		}

		u2fOffTimer = time.AfterFunc(u2fOffTimerDuration, func() {
			if lastMessage != notifier.U2F_OFF {
				notifiers.Range(func(_, v interface{}) bool {
					v.(chan notifier.Message) <- notifier.U2F_OFF
					return true
				})
				lastMessage = notifier.U2F_OFF
			}
		})
	}
}
