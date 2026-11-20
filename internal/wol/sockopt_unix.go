//go:build !windows

package wol

import "golang.org/x/sys/unix"

// enableBroadcast sets SO_BROADCAST on a socket. BSD and Linux both reject a
// datagram aimed at a broadcast address until this option is on.
func enableBroadcast(fd uintptr) error {
	return unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
}
