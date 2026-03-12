//go:build linux

package detector

import (
	"sync"
	"time"

	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"
)

// WatchGPGLinux watches for hints that YubiKey is maybe waiting for a touch on a GPG request.
// It uses Linux inotify to detect when shadowed private key files are opened.
func WatchGPGLinux(filesToWatch []string, requestGPGCheck chan bool, _ *sync.Map) {
	// No need for a buffered channel,
	// we are interested only in the first event, it's ok to skip all subsequent ones
	events := make(chan notify.EventInfo)

	initWatcher := func() {
		for _, file := range filesToWatch {
			if err := notify.Watch(file, events, notify.InOpen, notify.InDeleteSelf, notify.InMoveSelf); err != nil {
				log.Errorf("Failed to establish a watch on GPG file '%s': %v\n", file, err)
				return
			}
			log.Debugf("GPG watcher is watching '%s'...\n", file)
		}
	}

	initWatcher()
	defer notify.Stop(events)

	for event := range events {
		switch event.Event() {
		case notify.InOpen:
			select {
			case requestGPGCheck <- true:
			default:
			}
		default:
			log.Debugf("GPG received file event '%+v', recreating the watcher.", event.Event())
			notify.Stop(events)
			time.Sleep(5 * time.Second)
			initWatcher()
		}
	}
}
