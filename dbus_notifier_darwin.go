//go:build darwin

package main

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

func setupDbusNotifier(notifiers *sync.Map) {
	log.Warn("--dbus is not supported on macOS; flag ignored")
}
