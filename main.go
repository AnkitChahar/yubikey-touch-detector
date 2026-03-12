package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/proglottis/gpgme"
	log "github.com/sirupsen/logrus"

	"github.com/maximbaz/yubikey-touch-detector/detector"
	"github.com/maximbaz/yubikey-touch-detector/notifier"
)

// Override with -ldflags "-X main.version=xxx" when compiling not from a git-archive tarball
var version = "$Format:%(describe)$"

func main() {
	truthyValues := map[string]bool{"true": true, "yes": true, "1": true}

	envVerbose := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_VERBOSE"))]
	envNotify := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_NOTIFY"))]
	// Keep legacy env var for backwards compat on Linux.
	envLibnotify := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_LIBNOTIFY"))]
	envStdout := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_STDOUT"))]
	envNosocket := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_NOSOCKET"))]
	envDbus := truthyValues[strings.ToLower(os.Getenv("YUBIKEY_TOUCH_DETECTOR_DBUS"))]

	var printVersion bool
	var verbose bool
	var notify_ bool   // cross-platform desktop notification (libnotify on Linux, osascript on macOS)
	var libnotify bool // legacy Linux-only alias for --notify
	var stdout bool
	var nosocket bool
	var dbus bool

	flag.BoolVar(&printVersion, "version", false, "print version and exit")
	flag.BoolVar(&verbose, "v", envVerbose, "enable debug logging")
	flag.BoolVar(&notify_, "notify", envNotify || envLibnotify, "show desktop notifications (libnotify on Linux, osascript on macOS)")
	flag.BoolVar(&libnotify, "libnotify", envLibnotify, "show desktop notifications using libnotify (Linux only; alias for --notify)")
	flag.BoolVar(&stdout, "stdout", envStdout, "print notifications to stdout")
	flag.BoolVar(&nosocket, "no-socket", envNosocket, "disable unix socket notifier")
	flag.BoolVar(&dbus, "dbus", envDbus, "enable dbus server for IPC (Linux only)")
	flag.Parse()

	if printVersion {
		fmt.Println("YubiKey touch detector version:", appVersion())
		os.Exit(0)
	}

	if verbose {
		log.SetLevel(log.DebugLevel)
	}

	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
	log.Debug("Starting YubiKey touch detector")

	exits := &sync.Map{}
	go setupExitSignalWatch(exits)

	notifiers := &sync.Map{}

	if verbose {
		go notifier.SetupDebugNotifier(notifiers)
	}
	if !nosocket {
		go notifier.SetupUnixSocketNotifier(notifiers, exits)
	}
	if notify_ || libnotify {
		go notifier.SetupPlatformNotifier(notifiers)
	}
	if stdout {
		go notifier.SetupStdoutNotifier(notifiers)
	}
	if dbus {
		go setupDbusNotifier(notifiers)
	}

	strategy := detector.NewDetectorStrategy()
	go strategy.WatchU2F(notifiers)
	go strategy.WatchHMAC(notifiers)
	initGPGBasedDetectors(notifiers, exits, strategy)

	wait := make(chan bool)
	<-wait
}

func initGPGBasedDetectors(notifiers, exits *sync.Map, strategy detector.DetectorStrategy) {
	ctx, err := gpgme.New()
	if err != nil {
		log.Debugf("Cannot initialize GPG context: %v. Disabling GPG and SSH watchers.", err)
		return
	}

	if ctx.SetProtocol(gpgme.ProtocolAssuan) != nil {
		log.Debugf("Cannot initialize Assuan IPC: %v. Disabling GPG and SSH watchers.", err)
		return
	}

	var gpgPrivateKeysDirPath = path.Join(gpgme.GetDirInfo("homedir"), "private-keys-v1.d")
	if _, err := os.Stat(gpgPrivateKeysDirPath); err != nil {
		log.Debugf("Directory '%s' does not exist or cannot stat it\n", gpgPrivateKeysDirPath)
		return
	}

	filesToWatch, err := findShadowedPrivateKeys(gpgPrivateKeysDirPath)
	if err != nil {
		log.Debugf("Error finding shadowed private keys: %v\n", err)
		return
	}

	if len(filesToWatch) == 0 {
		log.Debugf("No shadowed private keys found.\n")
		return
	}

	requestGPGCheck := make(chan bool)
	go detector.CheckGPGOnRequest(requestGPGCheck, notifiers, ctx)
	go strategy.WatchGPG(filesToWatch, requestGPGCheck, exits)
	go detector.WatchSSH(requestGPGCheck, exits)
}

func findShadowedPrivateKeys(folderPath string) ([]string, error) {
	var result []string
	err := filepath.WalkDir(folderPath, func(path string, info os.DirEntry, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(data), "shadowed-private-key") {
			result = append(result, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func setupExitSignalWatch(exits *sync.Map) {
	exitSignal := make(chan os.Signal, 1)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)

	<-exitSignal
	println()

	exits.Range(func(_, v interface{}) bool {
		exit := v.(chan bool)
		exit <- true // Notify exit watcher
		<-exit       // Wait for confirmation
		return true
	})

	log.Debug("Stopping YubiKey touch detector")
	os.Exit(0)
}

func appVersion() string {
	if strings.HasPrefix(version, "$") {
		return "unknown"
	}
	return version
}
