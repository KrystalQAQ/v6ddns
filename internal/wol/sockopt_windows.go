//go:build windows

package wol

import "golang.org/x/sys/windows"

// enableBroadcast sets SO_BROADCAST on a socket. Winsock fails a send to a
// broadcast address with WSAEACCES until the option is on.
func enableBroadcast(fd uintptr) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_BROADCAST, 1)
}
