// Package autostart manages "run at login" for the GUI. The real work is in
// OS-specific files; each implements Enable, Disable and IsEnabled. Autostart
// entries always launch the executable with --tray so it stays in the tray.
package autostart

// Manager is implemented exactly once per build target.
type Manager interface {
	Enable(execPath string) error
	Disable() error
	IsEnabled() (bool, error)
}

// New returns the platform manager, or nil on unsupported platforms.
func New() Manager { return newManager() }
