//go:build linux

package main

import (
	"sync"

	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

func setupDbusNotifier(notifiers *sync.Map) {
	notifier.SetupDbusNotifier(notifiers)
}
