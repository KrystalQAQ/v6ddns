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

// RecordSource selects where an additional record's address comes from.
type RecordSource string

const (
	// SourceInterface reads an address from a local interface (the default).
	SourceInterface RecordSource = "interface"
	// SourceMAC reads a LAN device's GUA from the kernel neighbour table by MAC.
	SourceMAC RecordSource = "mac"
)

// AdditionalRecord is a DNS record beyond the primary one. Fields left empty
// inherit from the top-level configuration. This lets one daemon manage the
// router's own WAN address and several LAN devices at once.
type AdditionalRecord struct {
	Domain    string       `yaml:"domain"`
	Source    RecordSource `yaml:"source,omitempty"` // interface (default) or mac
	Interface string       `yaml:"interface,omitempty"`
	MAC       string       `yaml:"mac,omitempty"`
	Policy    TargetPolicy `yaml:"policy,omitempty"`
	Address   string       `yaml:"address,omitempty"`
	TTL       int          `yaml:"ttl,omitempty"`     // 0 inherits the top-level TTL.
	Proxied   *bool        `yaml:"proxied,omitempty"` // nil inherits the top-level value.
}

// RecordSpec is one fully-resolved record the engine should maintain. The
// primary record is built from the top-level fields; additional records are
// built from Config.Records with inherited defaults applied.
type RecordSpec struct {
	Domain    string
	Source    RecordSource
	Interface string
	MAC       string
	Policy    TargetPolicy
	Address   string
	TTL       int
	Proxied   bool
	Primary   bool
}

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

	// IPv4Domain, when non-empty, makes the engine maintain an A record for
	// this name containing the machine's public IPv4 address. It is independent
	// of the IPv6 records above and inherits their TTL and Proxied values.
	// Empty disables IPv4 handling.
	IPv4Domain string `yaml:"ipv4_domain,omitempty"`

	// Records are additional AAAA records maintained by the same daemon. The
	// top-level Domain remains the primary record; this list lets one process
	// publish the router's WAN address and several LAN devices by MAC.
	Records []AdditionalRecord `yaml:"records,omitempty"`

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

	// ListenPort is the TCP port the app opens on startup for inbound
	// reachability checks (default 38080). The app serves a tiny HTTP page on
	// it; the Cloudflare Worker connects to the configured domain on this port.
	ListenPort int `yaml:"listen_port"`

	// AdminPort is the port of the local web console (default 38081).
	AdminPort int `yaml:"admin_port,omitempty"`

	// AdminBind is where the web console listens (default 127.0.0.1). A
	// comma-separated list of concrete addresses is accepted, e.g.
	// "10.13.13.1,192.168.1.125" to serve both a WireGuard peer network and the
	// LAN. Unspecified addresses (0.0.0.0, ::) are refused: the console can
	// read and edit the Cloudflare token, so every exposure must be explicit.
	AdminBind string `yaml:"admin_bind,omitempty"`

	// AdminHosts is the comma-separated hostname allowlist for the console's
	// Host header when admin_bind contains a wildcard (0.0.0.0 or ::). It is
	// required for public binds: accepting every Host would defeat the
	// DNS-rebinding guard. Example: "v6.example.com".
	AdminHosts string `yaml:"admin_hosts,omitempty"`

	// InboundWorker is the Cloudflare Worker endpoint used for inbound checks.
	// Empty means "use the value from the --inbound-worker flag / default".
	InboundWorker string `yaml:"inbound_worker,omitempty"`

	// RequireInbound gates every AAAA change behind an external reachability
	// check: the candidate address is first published to ProbeHost, the
	// Cloudflare Worker must connect to ProbeHost:InboundPort, and only then is
	// the main domain's AAAA record updated. An unreachable candidate leaves
	// the existing record untouched (fail closed).
	RequireInbound bool `yaml:"require_inbound,omitempty"`

	// InboundPort is the TCP port the gate verifies. Zero means ListenPort,
	// which is the port the app itself listens on while the GUI runs.
	InboundPort int `yaml:"inbound_port,omitempty"`

	// ProbeBase is the name under which per-address probe records are created
	// (v6-<hex-address>.<ProbeBase>). Each candidate gets a fresh DNS name, so
	// a stale resolver cache can never validate the wrong address. Empty means
	// Domain. It must be Domain itself or a subdomain of it.
	ProbeBase string `yaml:"probe_base,omitempty"`
}

// Default returns a Config populated with conservative, usable defaults.
func Default() Config {
	return Config{
		TTL:          1,
		Proxied:      false,
		Interval:     "5m",
		Policy:       PolicyStableAuto,
		ProbeTimeout: "5s",
		ListenPort:   38080,
		AdminPort:    38081,
		AdminBind:    "127.0.0.1",
	}
}

// AdminBinds returns the concrete console bind addresses. An empty value means
// the loopback default; commas separate multiple addresses.
func (c Config) AdminBinds() []string {
	raw := strings.TrimSpace(c.AdminBind)
	if raw == "" {
		raw = Default().AdminBind
	}
	var out []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		addr := strings.TrimSpace(part)
		if addr == "" {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return []string{Default().AdminBind}
	}
	return out
}

// AdminHostsList returns the normalized, de-duplicated Host allowlist. The
// list is only consulted when the console is bound to a concrete address or a
// wildcard; it never widens the loopback allowance.
func (c Config) AdminHostsList() []string {
	raw := strings.TrimSpace(c.AdminHosts)
	if raw == "" {
		return nil
	}
	var out []string
	seen := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		host := strings.TrimSpace(strings.ToLower(part))
		host = strings.TrimSuffix(host, ".")
		host = strings.Trim(host, "[]")
		if host == "" {
			continue
		}
		if _, ok := seen[host]; ok {
			continue
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	return out
}

// HasWildcardBind reports whether admin_bind contains 0.0.0.0 or ::. Public
// binds are only accepted together with a non-empty admin_hosts and a console
// password from the environment.
func (c Config) HasWildcardBind() bool {
	for _, bind := range c.AdminBinds() {
		if ip := net.ParseIP(bind); ip != nil && ip.IsUnspecified() {
			return true
		}
	}
	return false
}

// RecordSpecs resolves the primary record plus every additional record into
// the concrete list the DDNS engine iterates. Defaults are inherited from the
// top-level fields; the primary record is always first.
func (c Config) RecordSpecs() []RecordSpec {
	primary := RecordSpec{
		Domain:    normalizeHost(c.Domain),
		Source:    SourceInterface,
		Interface: strings.TrimSpace(c.InterfaceName),
		Policy:    c.Policy,
		Address:   strings.TrimSpace(c.Address),
		TTL:       c.TTL,
		Proxied:   c.Proxied,
		Primary:   true,
	}
	out := make([]RecordSpec, 0, 1+len(c.Records))
	out = append(out, primary)
	for _, r := range c.Records {
		spec := RecordSpec{
			Domain:    normalizeHost(r.Domain),
			Source:    RecordSource(strings.ToLower(strings.TrimSpace(string(r.Source)))),
			Interface: strings.TrimSpace(r.Interface),
			MAC:       strings.TrimSpace(r.MAC),
			Policy:    TargetPolicy(strings.ToLower(strings.TrimSpace(string(r.Policy)))),
			Address:   strings.TrimSpace(r.Address),
			TTL:       r.TTL,
		}
		if spec.Source == "" {
			spec.Source = SourceInterface
		}
		if spec.Interface == "" {
			spec.Interface = primary.Interface
		}
		if spec.Policy == "" {
			spec.Policy = primary.Policy
		}
		if spec.TTL == 0 {
			spec.TTL = primary.TTL
		}
		if r.Proxied != nil {
			spec.Proxied = *r.Proxied
		} else {
			spec.Proxied = primary.Proxied
		}
		if hw, err := NormalizeMAC(spec.MAC); err == nil {
			spec.MAC = hw
		}
		out = append(out, spec)
	}
	return out
}

// IPv4DomainName returns the normalized A-record name, or "" when IPv4
// handling is disabled.
func (c Config) IPv4DomainName() string {
	return normalizeHost(c.IPv4Domain)
}

// ProbeBaseFor returns the base name used for the inbound gate's per-address
// probe record. The primary record honours the explicit probe_base setting;
// additional records use their own domain so the probe name always belongs to
// the record being changed.
func (c Config) ProbeBaseFor(spec RecordSpec) string {
	if spec.Primary {
		return c.EffectiveProbeBase()
	}
	return normalizeHost(spec.Domain)
}

// NormalizeMAC parses an EUI-48 MAC and returns it in lower-case colon form.
// Multicast and all-zero addresses are rejected because they can never name a
// neighbour-table entry.
func NormalizeMAC(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("mac is empty")
	}
	hw, err := net.ParseMAC(raw)
	if err != nil {
		return "", fmt.Errorf("invalid MAC %q: %w", raw, err)
	}
	if len(hw) != 6 {
		return "", fmt.Errorf("invalid MAC %q: expected 6 bytes, got %d", raw, len(hw))
	}
	if hw[0]&0x01 != 0 {
		return "", fmt.Errorf("invalid MAC %q: multicast bit is set", raw)
	}
	allZero := true
	for _, b := range hw {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", fmt.Errorf("invalid MAC %q: all-zero address", raw)
	}
	return strings.ToLower(hw.String()), nil
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
	if cfg.ListenPort == 0 {
		cfg.ListenPort = Default().ListenPort
	}
	if cfg.AdminPort == 0 {
		cfg.AdminPort = Default().AdminPort
	}
	if strings.TrimSpace(cfg.AdminBind) == "" {
		cfg.AdminBind = Default().AdminBind
	}
	cfg.AdminBind = strings.TrimSpace(cfg.AdminBind)
	cfg.AdminHosts = strings.TrimSpace(cfg.AdminHosts)
	cfg.IPv4Domain = normalizeHost(cfg.IPv4Domain)
	cfg.Policy = TargetPolicy(strings.ToLower(strings.TrimSpace(string(cfg.Policy))))
	if cfg.InterfaceName != "" {
		cfg.InterfaceName = strings.TrimSpace(cfg.InterfaceName)
	}
	if cfg.Address != "" {
		cfg.Address = strings.TrimSpace(cfg.Address)
	}
	for i := range cfg.Records {
		r := &cfg.Records[i]
		r.Domain = normalizeHost(r.Domain)
		r.Source = RecordSource(strings.ToLower(strings.TrimSpace(string(r.Source))))
		r.Interface = strings.TrimSpace(r.Interface)
		r.MAC = strings.TrimSpace(r.MAC)
		r.Policy = TargetPolicy(strings.ToLower(strings.TrimSpace(string(r.Policy))))
		r.Address = strings.TrimSpace(r.Address)
		if hw, err := NormalizeMAC(r.MAC); err == nil {
			r.MAC = hw
		}
	}
	return cfg, nil
}

// Validate checks configuration consistency. It is called by Save and may also
// be called by the TUI before committing form values.
func (c Config) Validate() error {
	// The Cloudflare account fields are required: the DDNS engine and the
	// inbound check both use the configured domain as the record to bind.
	if strings.TrimSpace(c.APIToken) == "" {
		return fmt.Errorf("config: api_token is required")
	}
	if strings.TrimSpace(c.ZoneID) == "" {
		return fmt.Errorf("config: zone_id is required")
	}
	if strings.TrimSpace(c.Domain) == "" {
		return fmt.Errorf("config: domain is required")
	}
	if net.ParseIP(strings.TrimSpace(c.Domain)) != nil {
		return fmt.Errorf("config: domain must be a hostname, got %q", c.Domain)
	}
	if c.IPv4Domain != "" && !isHostname(normalizeHost(c.IPv4Domain)) {
		return fmt.Errorf("config: ipv4_domain %q is not a valid hostname", c.IPv4Domain)
	}
	if c.ListenPort < 1 || c.ListenPort > 65535 {
		return fmt.Errorf("config: listen_port must be 1-65535, got %d", c.ListenPort)
	}
	if c.ListenPort == 25 {
		return fmt.Errorf("config: listen_port 25 is not allowed")
	}
	if c.AdminPort < 1 || c.AdminPort > 65535 {
		return fmt.Errorf("config: admin_port must be 1-65535, got %d", c.AdminPort)
	}
	if c.AdminPort == c.ListenPort {
		return fmt.Errorf("config: admin_port must differ from listen_port (%d)", c.ListenPort)
	}
	for _, bind := range c.AdminBinds() {
		ip := net.ParseIP(bind)
		if ip == nil {
			return fmt.Errorf("config: admin_bind must be an IP address, got %q", bind)
		}
		if ip.IsMulticast() {
			return fmt.Errorf("config: admin_bind must not be multicast, got %q", bind)
		}
	}
	hosts := c.AdminHostsList()
	for _, host := range hosts {
		if host == "*" || host == "" {
			return fmt.Errorf("config: admin_hosts must list concrete hostnames, got %q", host)
		}
		if net.ParseIP(host) == nil && !isHostname(host) {
			return fmt.Errorf("config: admin_hosts contains an invalid hostname %q", host)
		}
	}
	if c.HasWildcardBind() && len(hosts) == 0 {
		return fmt.Errorf("config: admin_bind with a wildcard address requires admin_hosts (e.g. v6.example.com)")
	}
	if c.InboundPort < 0 || c.InboundPort > 65535 {
		return fmt.Errorf("config: inbound_port must be 0 (use listen_port) or 1-65535, got %d", c.InboundPort)
	}
	if c.InboundPort == 25 {
		return fmt.Errorf("config: inbound_port 25 is not allowed")
	}
	if c.RequireInbound {
		if c.Proxied {
			return fmt.Errorf("config: require_inbound needs proxied=false so the Worker reaches the host directly")
		}
		base := c.EffectiveProbeBase()
		if !isHostname(base) {
			return fmt.Errorf("config: probe_base %q is not a valid hostname", base)
		}
		domain := normalizeHost(c.Domain)
		if base != domain && !strings.HasSuffix(base, "."+domain) {
			return fmt.Errorf("config: probe_base %q must be %q or a subdomain of it", base, domain)
		}
	}
	if _, err := time.ParseDuration(c.Interval); err != nil {
		return fmt.Errorf("config: invalid interval %q: %w", c.Interval, err)
	}
	if c.ProbeTimeout != "" {
		if _, err := time.ParseDuration(c.ProbeTimeout); err != nil {
			return fmt.Errorf("config: invalid probe timeout %q: %w", c.ProbeTimeout, err)
		}
	}

	seenDomains := make(map[string]struct{})
	for _, spec := range c.RecordSpecs() {
		domain := normalizeHost(spec.Domain)
		if !isHostname(domain) {
			return fmt.Errorf("config: record domain %q is not a valid hostname", spec.Domain)
		}
		if _, ok := seenDomains[domain]; ok {
			return fmt.Errorf("config: duplicate record domain %q", domain)
		}
		seenDomains[domain] = struct{}{}

		switch spec.Source {
		case SourceInterface, SourceMAC:
		default:
			return fmt.Errorf("config: record %q has unknown source %q", domain, spec.Source)
		}
		if spec.Source == SourceMAC {
			if _, err := NormalizeMAC(spec.MAC); err != nil {
				return fmt.Errorf("config: record %q: %w", domain, err)
			}
			if spec.Policy == PolicyManual {
				return fmt.Errorf("config: record %q: source=mac cannot use manual policy", domain)
			}
		}

		switch spec.Policy {
		case PolicyManual, PolicyStableAuto, PolicyAnyReachable:
		default:
			return fmt.Errorf("config: record %q has unknown target policy %q", domain, spec.Policy)
		}
		if spec.TTL < 0 {
			return fmt.Errorf("config: record %q: TTL must be >= 0, got %d", domain, spec.TTL)
		}
		if spec.Policy == PolicyManual {
			ip := net.ParseIP(spec.Address)
			if ip == nil || ip.To4() != nil {
				return fmt.Errorf("config: record %q: manual policy requires a valid IPv6 address, got %q", domain, spec.Address)
			}
		}
		if c.RequireInbound && spec.Proxied {
			return fmt.Errorf("config: record %q: require_inbound needs proxied=false so the Worker reaches the host directly", domain)
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

// EffectiveInboundPort returns the TCP port the inbound gate checks. An
// explicit inbound_port wins; otherwise the app's own listen_port is used.
func (c Config) EffectiveInboundPort() int {
	if c.InboundPort > 0 {
		return c.InboundPort
	}
	return c.ListenPort
}

// EffectiveProbeBase returns the base name under which the gate creates its
// per-address records. It defaults to Domain; the result is always lowercase
// and has no trailing dot.
func (c Config) EffectiveProbeBase() string {
	if h := normalizeHost(c.ProbeBase); h != "" {
		return h
	}
	return normalizeHost(c.Domain)
}

func normalizeHost(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

// isHostname is the relaxed hostname check used for ProbeHost. The Cloudflare
// Worker's connect() also rejects IP literals, so those are refused here.
func isHostname(s string) bool {
	if s == "" || len(s) > 253 || net.ParseIP(s) != nil || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
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
