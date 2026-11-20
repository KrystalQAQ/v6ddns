//go:build linux

package autostart

import (
	"fmt"
	"os"
	"path/filepath"
)

type linuxManager struct{}

func newManager() Manager { return linuxManager{} }

func desktopPath() (string, error) {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "autostart", "v6ddns.desktop"), nil
}

func (linuxManager) Enable(execPath string) error {
	path, err := desktopPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	content := fmt.Sprintf(`[Desktop Entry]
Type=Application
Name=v6ddns
Exec=%q --tray
NoDisplay=true
X-GNOME-Autostart-enabled=true
`, execPath)
	return os.WriteFile(path, []byte(content), 0600)
}

func (linuxManager) Disable() error {
	path, err := desktopPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (linuxManager) IsEnabled() (bool, error) {
	path, err := desktopPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	return err == nil, nil
}
