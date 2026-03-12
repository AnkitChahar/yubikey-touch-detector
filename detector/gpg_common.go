package detector

import (
	"sync"
	"time"

	"github.com/proglottis/gpgme"
	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// CheckGPGOnRequest checks whether YubiKey is actually waiting for a touch on a GPG request.
// This works by sending an Assuan LEARN command and timing the response: if the agent takes
// more than 400ms to reply, the YubiKey is waiting for a physical touch.
// This implementation is platform-independent (uses GPGME, available on Linux and macOS).
func CheckGPGOnRequest(requestGPGCheck chan bool, notifiers *sync.Map, ctx *gpgme.Context) {
	check := func(response chan error, ctx *gpgme.Context, t *time.Timer) {
		err := ctx.AssuanSend("LEARN", nil, nil, func(status, args string) error {
			log.Debugf("AssuanSend/status: %v, %v", status, args)
			return nil
		})
		if !t.Stop() {
			response <- err
		}
	}
	for range requestGPGCheck {
		resp := make(chan error)

		t := time.AfterFunc(400*time.Millisecond, func() {
			notifiers.Range(func(_, v interface{}) bool {
				v.(chan notifier.Message) <- notifier.GPG_ON
				return true
			})
			err := <-resp
			if err != nil {
				log.Errorf("Agent returned an error: %v", err)
			}
			notifiers.Range(func(_, v interface{}) bool {
				v.(chan notifier.Message) <- notifier.GPG_OFF
				return true
			})
		})

		time.Sleep(200 * time.Millisecond) // wait for GPG to start talking with scdaemon
		check(resp, ctx, t)
	}
}
