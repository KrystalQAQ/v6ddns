//go:build !darwin && !windows && !linux

package autostart

import "fmt"

type unsupported struct{}

func newManager() Manager { return unsupported{} }

func (unsupported) Enable(string) error { return fmt.Errorf("autostart: unsupported platform") }
func (unsupported) Disable() error      { return fmt.Errorf("autostart: unsupported platform") }
func (unsupported) IsEnabled() (bool, error) {
	return false, fmt.Errorf("autostart: unsupported platform")
}
