//go:build linux

package detector

import (
	"os"
	"path"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/rjeczalik/notify"
	log "github.com/sirupsen/logrus"
	"github.com/vtolstov/go-ioctl"
)

var (
	// https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h
	HIDIOCGRDESCSIZE = ioctl.IOR('H', 1, 4)
	HIDIOCGRDESC     = ioctl.IOR('H', 2, unsafe.Sizeof(hidrawDescriptor{}))
)

// https://github.com/torvalds/linux/blob/master/include/uapi/linux/hidraw.h
type hidrawDescriptor struct {
	Size  uint32
	Value [4096]uint8
}

// WatchU2F watches for U2F/FIDO2 touch events using Linux hidraw devices.
func WatchU2F(notifiers *sync.Map) {
	checkAndInitWatcher := func(devicePath string) {
		if isFidoU2FDeviceLinux(devicePath) {
			dev, err := os.Open(devicePath)
			if err != nil {
				log.Errorf("Cannot open device '%v' to run U2F watcher: %v", devicePath, err)
				return
			}
			go runU2FPacketWatcher(dev, notifiers)
		}
	}

	devicesEvents := initInotifyWatcher("U2F", "/dev", notify.Create)
	defer notify.Stop(devicesEvents)

	if devices, err := os.ReadDir("/dev"); err == nil {
		for _, device := range devices {
			checkAndInitWatcher(path.Join("/dev", device.Name()))
		}
	} else {
		log.Errorf("Cannot list devices in '/dev' to find connected YubiKeys: %v", err)
	}

	for event := range devicesEvents {
		// Give a second for device to initialize before establishing a watcher.
		time.Sleep(1 * time.Second)
		checkAndInitWatcher(event.Path())
	}
}

func isFidoU2FDeviceLinux(devicePath string) bool {
	if !strings.HasPrefix(devicePath, "/dev/hidraw") {
		return false
	}

	device, err := os.Open(devicePath)
	if err != nil {
		return false
	}
	defer device.Close()

	var size uint32
	err = ioctl.IOCTL(device.Fd(), HIDIOCGRDESCSIZE, uintptr(unsafe.Pointer(&size)))
	if err != nil {
		log.Warnf("Cannot get descriptor size for device '%v': %v", devicePath, err)
		return false
	}

	data := hidrawDescriptor{Size: size}
	err = ioctl.IOCTL(device.Fd(), HIDIOCGRDESC, uintptr(unsafe.Pointer(&data)))
	if err != nil {
		log.Warnf("Cannot get descriptor for device '%v': %v", devicePath, err)
		return false
	}

	isFido := false
	hasU2F := false
	for i := uint32(0); i < size; {
		prefix := data.Value[i]
		tag := (prefix & 0b11110000) >> 4
		typ := (prefix & 0b00001100) >> 2
		size := prefix & 0b00000011

		val1b := data.Value[i+1]
		val2b := int(data.Value[i+1]) | (int(data.Value[i+2]) << 8)

		if typ == HID_ITEM_TYPE_GLOBAL && tag == HID_GLOBAL_ITEM_TAG_USAGE_PAGE && val2b == FIDO_USAGE_PAGE {
			isFido = true
		} else if typ == HID_ITEM_TYPE_LOCAL && tag == HID_LOCAL_ITEM_TAG_USAGE && val1b == FIDO_USAGE_CTAPHID {
			hasU2F = true
		}

		if isFido && hasU2F {
			return true
		}

		i += uint32(size) + 1
	}

	return false
}
