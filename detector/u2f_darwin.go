//go:build darwin

package detector

import (
	"bufio"
	"encoding/json"
	"os/exec"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

type u2fLogEntry struct {
	EventMessage string `json:"eventMessage"`
}

// WatchU2F detects U2F/FIDO2 touch events on macOS by watching kernel IOHIDFamily
// log messages. This never opens the FIDO HID device, so browsers can use WebAuthn
// concurrently.
func WatchU2F(notifiers *sync.Map) {
	predicate := `processImagePath == "/kernel" AND senderImagePath ENDSWITH "IOHIDFamily"`
	cmd := exec.Command("log", "stream", "--level", "debug", "--style", "ndjson", "--predicate", predicate)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("U2F: cannot create log stream pipe: %v", err)
		return
	}
	if err := cmd.Start(); err != nil {
		log.Errorf("U2F: cannot start log stream: %v", err)
		return
	}
	defer cmd.Process.Kill()

	// Map of IOHIDLibUserClient handles that belong to a YubiKey device.
	yubiKeyClients := map[string]bool{}
	lastMessage := notifier.U2F_OFF
	var u2fOffTimer *time.Timer

	broadcast := func(msg notifier.Message) {
		if lastMessage == msg {
			return
		}
		notifiers.Range(func(_, v interface{}) bool {
			v.(chan notifier.Message) <- msg
			return true
		})
		lastMessage = msg
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		var entry u2fLogEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}

		msg := entry.EventMessage

		// e.g., "AppleUserUSBHostHIDDevice:0x100000c81 open by IOHIDLibUserClient:0x10016f869 (0x1)"
		if strings.Contains(msg, "AppleUserUSBHostHIDDevice:") && strings.Contains(msg, "open by IOHIDLibUserClient:") {
			parts := strings.SplitN(msg, " open by ", 2)
			if len(parts) == 2 {
				clientID := strings.Fields(parts[1])[0]
				yubiKeyClients[clientID] = true
				log.Debugf("U2F: registered YubiKey HID client %v", clientID)
			}
		}

		// e.g., "IOHIDLibUserClient:0x10016f869 startQueue"
		if strings.HasSuffix(msg, "startQueue") {
			clientID := strings.Fields(msg)[0]
			if yubiKeyClients[clientID] {
				log.Debugf("U2F: startQueue for YubiKey client %v", clientID)
				if u2fOffTimer != nil {
					u2fOffTimer.Stop()
				}
				broadcast(notifier.U2F_ON)
				u2fOffTimer = time.AfterFunc(2*time.Second, func() {
					broadcast(notifier.U2F_OFF)
				})
			}
		} else if strings.HasSuffix(msg, "stopQueue") {
			clientID := strings.Fields(msg)[0]
			if yubiKeyClients[clientID] {
				log.Debugf("U2F: stopQueue for YubiKey client %v", clientID)
				if u2fOffTimer != nil {
					u2fOffTimer.Stop()
				}
				broadcast(notifier.U2F_OFF)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Errorf("U2F: log stream scanner error: %v", err)
	}
}
