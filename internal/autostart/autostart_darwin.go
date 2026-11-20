//go:build darwin

package autostart

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const label = "com.krystalqaq.v6ddns"

type darwinManager struct{}

func newManager() Manager { return darwinManager{} }

func plistPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

func (darwinManager) Enable(execPath string) error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	xml := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key><array>
    <string>%s</string><string>--tray</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict></plist>
`, label, execPath)
	if err := os.WriteFile(path, []byte(xml), 0600); err != nil {
		return err
	}
	// The plist is picked up on next login even if bootstrap fails (e.g. an
	// agent is already loaded); log but do not fail in that case.
	_ = exec.Command("launchctl", "bootout", "gui/"+fmt.Sprint(os.Getuid()), path).Run()
	if out, err := exec.Command("launchctl", "bootstrap", "gui/"+fmt.Sprint(os.Getuid()), path).CombinedOutput(); err != nil {
		_ = out
	}
	return nil
}

func (darwinManager) Disable() error {
	path, err := plistPath()
	if err != nil {
		return err
	}
	_ = exec.Command("launchctl", "bootout", "gui/"+fmt.Sprint(os.Getuid()), path).Run()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (darwinManager) IsEnabled() (bool, error) {
	path, err := plistPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(path)
	return err == nil, nil
}
