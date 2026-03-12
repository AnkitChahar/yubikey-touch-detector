//go:build darwin

package detector

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
)

// WatchGPGDarwin watches for GPG touch events on macOS by proxying the gpg-agent
// Unix socket. Every time traffic flows through the agent socket (indicating a GPG
// operation is in progress), requestGPGCheck is signalled. CheckGPGOnRequest then
// uses GPGME Assuan to confirm whether the YubiKey is actually waiting for a touch.
//
// filesToWatch is accepted for interface compatibility with the Linux strategy but
// is ignored on Darwin — socket proxying provides a more reliable trigger.
//
// exits is used to register a cleanup handler that restores the original socket on
// graceful shutdown, preventing the ".original" stale-socket warning on next start.
func WatchGPGDarwin(filesToWatch []string, requestGPGCheck chan bool, exits *sync.Map) {
	socketFile := findGPGAgentSocket()
	if socketFile == "" {
		log.Error("GPG Darwin watcher: cannot find gpg-agent socket; disabling GPG touch detection")
		return
	}

	if _, err := os.Stat(socketFile); err != nil {
		log.Errorf("GPG Darwin watcher: socket '%v' does not exist: %v", socketFile, err)
		return
	}

	originalSocketFile := socketFile + ".original"

	// Recover from a previous unclean exit where the proxy was left behind.
	if _, err := os.Stat(originalSocketFile); err == nil {
		log.Warnf("GPG Darwin watcher: '%v' already exists, attempting recovery", originalSocketFile)
		if err = os.Remove(socketFile); err != nil {
			log.Errorf("GPG Darwin watcher: cannot remove stale proxy socket: %v", err)
			return
		}
	} else {
		if err := os.Rename(socketFile, originalSocketFile); err != nil {
			log.Errorf("GPG Darwin watcher: cannot move original socket to set up proxy: %v", err)
			return
		}
	}

	proxySocket, err := net.Listen("unix", socketFile)
	if err != nil {
		log.Errorf("GPG Darwin watcher: cannot create proxy socket at '%v': %v", socketFile, err)
		_ = os.Rename(originalSocketFile, socketFile)
		return
	}
	log.Debugf("GPG Darwin watcher proxying '%v' → '%v'", socketFile, originalSocketFile)

	// Register exit handler to restore the original socket on graceful shutdown.
	exit := make(chan bool)
	exits.Store("detector/gpg_darwin", exit)
	go func() {
		<-exit
		if err := proxySocket.Close(); err != nil {
			log.Error("GPG Darwin watcher: cannot close proxy socket: ", err)
		}
		if err := os.Rename(originalSocketFile, socketFile); err != nil {
			log.Error("GPG Darwin watcher: cannot restore original socket: ", err)
		}
		exit <- true
	}()

	for {
		proxyConn, err := proxySocket.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Errorf("GPG Darwin watcher: accept error: %v", err)
			}
			return
		}

		// gpg-agent may have restarted. Try the .original socket first; if that
		// fails, fall back to the agent-socket path reported by gpgconf so we
		// can still forward even if the agent recreated its socket.
		originalConn, err := net.Dial("unix", originalSocketFile)
		if err != nil {
			log.Debugf("GPG Darwin watcher: .original socket unavailable (%v), trying gpgconf fallback", err)
			fallback := findGPGAgentFallbackSocket(socketFile)
			if fallback == "" {
				log.Warn("GPG Darwin watcher: no reachable gpg-agent socket; dropping connection")
				_ = proxyConn.Close()
				continue
			}
			originalConn, err = net.Dial("unix", fallback)
			if err != nil {
				log.Warnf("GPG Darwin watcher: fallback socket also unreachable: %v", err)
				_ = proxyConn.Close()
				continue
			}
		}
		go proxyUnixSocket(proxyConn, originalConn, requestGPGCheck)
		go proxyUnixSocket(originalConn, proxyConn, requestGPGCheck)
	}
}

// findGPGAgentFallbackSocket returns a reachable gpg-agent socket path that is
// not the proxy socket itself (used when .original becomes stale after agent restart).
func findGPGAgentFallbackSocket(proxyPath string) string {
	out, err := exec.Command("gpgconf", "--list-dirs", "agent-socket").Output()
	if err != nil {
		return ""
	}
	p := strings.TrimSpace(string(out))
	if p == "" || p == proxyPath {
		return ""
	}
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

func findGPGAgentSocket() string {
	out, err := exec.Command("gpgconf", "--list-dirs", "agent-socket").Output()
	if err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p
		}
	}
	home := os.Getenv("GNUPGHOME")
	if home == "" {
		home = os.ExpandEnv("$HOME/.gnupg")
	}
	return home + "/S.gpg-agent"
}
