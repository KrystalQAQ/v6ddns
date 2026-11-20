// Package browser opens a URL in the user's default browser. It is used only
// for the loopback console; the process never opens remote pages on its own.
package browser

import (
	"os/exec"
	"runtime"
)

// Open launches the default handler for url. It returns as soon as the
// launcher process starts, so a slow browser never blocks startup.
func Open(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
