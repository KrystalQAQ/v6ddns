// Package config defines the v6ddns configuration schema and provides
// YAML-backed loading and atomic saving under the user config directory.
package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// AppDir is the application subdirectory under os.UserConfigDir().
	AppDir = "v6ddns"
	// FileName is the default configuration file name.
	FileName = "config.yaml"
	// fileMode is restrictive because the file contains an API token (0600).
	fileMode = 0600
	// dirMode allows the owner to traverse and list the config directory.
	dirMode = 0700
)

// TargetPolicy selects how the DDNS engine picks the IPv6 address to publish.
// Values are case-insensitive when parsed from YAML.
type TargetPolicy string

const (
	// PolicyManual uses Address, the manually specified IPv6, without probing it.
	PolicyManual TargetPolicy = "manual"
	// PolicyStableAuto picks a stable, publicly reachable GUA automatically.
	PolicyStableAuto TargetPolicy = "stable-auto"
	// PolicyAnyReachable picks any reachable GUA automatically and emits a warning.
	PolicyAnyReachable TargetPolicy = "any-reachable"
)

// ProbeTargets are the public IPv6 endpoints used by the source-bound TCP
// reachability probe. Ali DNS is the primary target (verified reachable from
// en0's GUA on the reference machine); Cloudflare DNS is a fallback.
// Port 443 is used because it is almost always allowed outbound.
var ProbeTargets = []string{
	"[2400:3200::1]:443",
	"[2606:4700::1111]:443",
}

// Config is the persisted configuration. Fields are tagged for yaml.v3 and
// carry safe defaults via Default().
type Config struct {
	APIToken string `yaml:"api_token"`
	ZoneID   string `yaml:"zone_id"`
	Domain   string `yaml:"domain"`

	TTL     int  `yaml:"ttl"`     // 1 means "automatic" in the Cloudflare API.
	Proxied bool `yaml:"proxied"` // false = DNS only (grey cloud), required for direct IPv6.

	InterfaceName string `yaml:"interface_name"` // Empty means "all interfaces".
	Interval      string `yaml:"interval"`       // Go duration, e.g. "5m".

	Policy  TargetPolicy `yaml:"policy"`
	Address string       `yaml:"address"` // Manual IPv6, used when Policy == PolicyManual.

	// ProbeTargets optionally overrides the default reachability targets.
	ProbeTargets []string `yaml:"probe_targets,omitempty"`

	// ProbeTimeout is the Go duration for each individual network probe (default 5s).
	ProbeTimeout string `yaml:"probe_timeout,omitempty"`
}

// Default returns a Config populated with conservative, usable defaults.
func Default() Config {
	return Config{
		TTL:          1,
		Proxied:      false,
		Interval:     "5m",
		Policy:       PolicyStableAuto,
		ProbeTimeout: "5s",
	}
}

// Loader reads configuration. It is the read half of the persistence contract
// consumed by main.go and the TUI; tests and alternate backends can implement it.
type Loader interface {
	// Load returns the configuration at the path configured for this loader.
	// When the file does not exist it returns Default() and a nil error.
	Load() (Config, error)
}

// Store writes configuration. It is the write half of the persistence contract;
// implementations must persist the API token with restrictive file permissions.
type Store interface {
	// Save writes cfg to the path configured for this store, creating parent
	// directories as needed. Existing files are replaced atomically.
	Save(cfg Config) error
	// Path returns the resolved path that Load and Save operate on.
	Path() string
}

// FileStore is the YAML-backed implementation of Loader and Store.
type FileStore struct {
	path string
}

// NewFileStoreWithPath creates a store bound to an explicit path.
// It is primarily useful for tests and for the --config CLI flag.
func NewFileStoreWithPath(path string) *FileStore {
	return &FileStore{path: path}
}

// NewFileStore creates a store at os.UserConfigDir()/v6ddns/config.yaml.
func NewFileStore() (*FileStore, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return nil, fmt.Errorf("config: locate user config directory: %w", err)
	}
	return &FileStore{path: filepath.Join(dir, AppDir, FileName)}, nil
}

// Path implements Store.
func (s *FileStore) Path() string { return s.path }

// Load implements Loader. A missing file yields Default() without an error.
func (s *FileStore) Load() (Config, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", s.path, err)
	}
	return parse(data)
}

// Save implements Store. It writes via a temporary file and renames so that a
// crash cannot leave a partially written YAML document. The final file mode is
// 0600 at creation; on replacement of an existing file, its mode is enforced.
func (s *FileStore) Save(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("config: create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".config-*.yaml")
	if err != nil {
		return fmt.Errorf("config: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := tmp.Chmod(fileMode); err != nil {
		tmp.Close()
		return fmt.Errorf("config: set permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("config: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("config: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("config: rename into place: %w", err)
	}
	// Rename preserves the temp file's 0600 mode, but enforce it explicitly for
	// filesystems/platforms that may inherit a different mode.
	if err := os.Chmod(s.path, fileMode); err != nil {
		return fmt.Errorf("config: enforce permissions: %w", err)
	}
	return nil
}

// parse decodes YAML and applies defaults to zero-valued fields.
func parse(data []byte) (Config, error) {
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("config: parse YAML: %w", err)
	}
	// yaml.v3 leaves an explicitly present but empty value as zero; restore
	// defaults for the common unset case.
	if cfg.TTL == 0 {
		cfg.TTL = 1
	}
	if cfg.Interval == "" {
		cfg.Interval = Default().Interval
	}
	if cfg.ProbeTimeout == "" {
		cfg.ProbeTimeout = Default().ProbeTimeout
	}
	if cfg.Policy == "" {
		cfg.Policy = Default().Policy
	}
	cfg.Policy = TargetPolicy(strings.ToLower(strings.TrimSpace(string(cfg.Policy))))
	if cfg.InterfaceName != "" {
		cfg.InterfaceName = strings.TrimSpace(cfg.InterfaceName)
	}
	if cfg.Address != "" {
		cfg.Address = strings.TrimSpace(cfg.Address)
	}
	return cfg, nil
}

// Validate checks configuration consistency. It is called by Save and may also
// be called by the TUI before committing form values.
func (c Config) Validate() error {
	switch c.Policy {
	case PolicyManual, PolicyStableAuto, PolicyAnyReachable:
	default:
		return fmt.Errorf("config: unknown target policy %q", c.Policy)
	}
	if c.TTL < 0 {
		return fmt.Errorf("config: TTL must be >= 0, got %d", c.TTL)
	}
	if _, err := time.ParseDuration(c.Interval); err != nil {
		return fmt.Errorf("config: invalid interval %q: %w", c.Interval, err)
	}
	if c.ProbeTimeout != "" {
		if _, err := time.ParseDuration(c.ProbeTimeout); err != nil {
			return fmt.Errorf("config: invalid probe timeout %q: %w", c.ProbeTimeout, err)
		}
	}
	if c.Policy == PolicyManual {
		ip := net.ParseIP(c.Address)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("config: manual policy requires a valid IPv6 address, got %q", c.Address)
		}
	}
	for _, target := range c.effectiveProbeTargets() {
		if _, _, err := net.SplitHostPort(target); err != nil {
			return fmt.Errorf("config: invalid probe target %q: %w", target, err)
		}
	}
	return nil
}

// ProbeTargetsToUse returns the configured probe targets, or the package
// defaults if none were configured.
func (c Config) ProbeTargetsToUse() []string {
	return c.effectiveProbeTargets()
}

func (c Config) effectiveProbeTargets() []string {
	if len(c.ProbeTargets) > 0 {
		return c.ProbeTargets
	}
	return ProbeTargets
}

// MaskToken replaces every occurrence of the configured API token with "***".
// It is the canonical way to make a config safe to print or log. A short or
// empty token is left untouched to avoid masking unrelated text.
func (c Config) MaskToken(s string) string {
	return MaskToken(s, c.APIToken)
}

// MaskToken replaces every occurrence of token inside s with "***".
// Tokens shorter than 4 characters are ignored to avoid accidental over-masking.
func MaskToken(s, token string) string {
	if token == "" || len(token) < 4 || s == "" {
		return s
	}
	return strings.ReplaceAll(s, token, "***")
}
