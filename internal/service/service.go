// Package service owns the long-running v6ddns state shared by the tray, the
// local web console and the daemon loop. It has no UI dependencies: everything
// is exposed as methods returning plain data that HTTP handlers and the tray
// can render.
package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/autostart"
	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

// Options is everything main.go hands to the service.
type Options struct {
	Config    config.Config
	Store     daemon.ConfigStore
	Factory   daemon.DepsFactory
	WorkerURL string
	AutoMgr   autostart.Manager
	Buffer    *log.Buffer
	Logger    *log.Logger
	Version   string
	// Neighbors is the neighbour-table reader used by the discovery page.
	// Nil selects the OS-backed provider.
	Neighbors ipv6.NeighborProvider
}

// Service is safe for concurrent use by the tray, the HTTP server and the
// daemon loop.
type Service struct {
	mu        sync.RWMutex
	cfg       config.Config
	store     daemon.ConfigStore
	factory   daemon.DepsFactory
	worker    string
	autoMgr   autostart.Manager
	buf       *log.Buffer
	logger    *log.Logger
	version   string
	neighbors ipv6.NeighborProvider

	interval    time.Duration
	lastEvent   daemon.Event
	addrs       []ipv6.Address
	lastInbound *InboundStatus
	adminURL    string

	listenMu  sync.Mutex
	listener  *inbound.Server
	listenErr error

	busy    atomic.Bool
	onEvent atomic.Pointer[func(daemon.Event)]
}

// New validates the interval and returns a service that is ready to Start.
func New(opts Options) (*Service, error) {
	interval, err := time.ParseDuration(opts.Config.Interval)
	if err != nil {
		return nil, fmt.Errorf("invalid interval: %w", err)
	}
	if opts.Logger == nil {
		opts.Logger = log.Default
	}
	neighbors := opts.Neighbors
	if neighbors == nil {
		neighbors = ipv6.SystemNeighborProvider{}
	}
	return &Service{
		cfg:       opts.Config,
		store:     opts.Store,
		factory:   opts.Factory,
		worker:    opts.WorkerURL,
		autoMgr:   opts.AutoMgr,
		buf:       opts.Buffer,
		logger:    opts.Logger,
		version:   opts.Version,
		neighbors: neighbors,
		interval:  interval,
	}, nil
}

// SetEventHandler installs a callback invoked after every completed cycle.
// The tray uses it to refresh its menu labels.
func (s *Service) SetEventHandler(fn func(daemon.Event)) {
	s.onEvent.Store(&fn)
}

// Start binds the public listener and launches the DDNS loop.
func (s *Service) Start(ctx context.Context) {
	s.startListener(s.currentConfig().ListenPort)
	go daemon.RunLoop(ctx, s.currentConfig(), s.store, s.factory, s.interval, s.onDaemonEvent)
}

// Close stops the public listener.
func (s *Service) Close() {
	s.listenMu.Lock()
	srv := s.listener
	s.listener = nil
	s.listenMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (s *Service) currentConfig() config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// Config returns a copy of the active configuration.
func (s *Service) Config() config.Config { return s.currentConfig() }

// ConfigPath returns the YAML file backing the active configuration.
func (s *Service) ConfigPath() string { return s.store.Path() }

// SetAdminURL records the console address for display in status responses.
func (s *Service) SetAdminURL(u string) {
	s.mu.Lock()
	s.adminURL = u
	s.mu.Unlock()
}

// ---- listener -------------------------------------------------------------

func (s *Service) startListener(port int) {
	s.listenMu.Lock()
	old := s.listener
	s.listener = nil
	s.listenErr = nil
	s.listenMu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	srv, err := inbound.StartServer(port)
	s.listenMu.Lock()
	s.listener, s.listenErr = srv, err
	s.listenMu.Unlock()
	if err != nil {
		s.logger.Error("inbound listener failed", "port", port, "error", err)
		return
	}
	s.logger.Info("inbound listener started", "addr", srv.Addr())
}

// ---- daemon events --------------------------------------------------------

func (s *Service) onDaemonEvent(ev daemon.Event) {
	s.mu.Lock()
	s.lastEvent = ev
	if len(ev.Addrs) > 0 {
		s.addrs = ev.Addrs
	}
	s.mu.Unlock()
	if fn := s.onEvent.Load(); fn != nil {
		(*fn)(ev)
	}
}

// ---- operations -----------------------------------------------------------

// Detect enumerates local IPv6 addresses and probes them.
func (s *Service) Detect(ctx context.Context) ([]ipv6.Address, error) {
	detector, _, _ := s.factory(s.currentConfig())
	if detector == nil {
		return nil, errors.New("没有可用的 IPv6 检测器")
	}
	addrs, err := detector.Detect(ctx)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.addrs = addrs
	s.mu.Unlock()
	return addrs, nil
}

// Neighbors returns the kernel's IPv6 neighbour table. It is passive: a device
// that has not used IPv6 recently may be absent until it sends traffic.
func (s *Service) Neighbors(ctx context.Context) ([]ipv6.Neighbor, error) {
	if s.neighbors == nil {
		return nil, errors.New("没有可用的邻居表读取器")
	}
	return s.neighbors.Neighbors(ctx)
}

// ErrBusy is returned when another manual cycle is already running.
var ErrBusy = errors.New("已有更新任务在运行，请稍候")

// Update runs one detect-and-publish cycle outside the daemon loop.
func (s *Service) Update(ctx context.Context) (daemon.Event, error) {
	if !s.busy.CompareAndSwap(false, true) {
		return daemon.Event{}, ErrBusy
	}
	defer s.busy.Store(false)

	cfg := s.currentConfig()
	s.logger.Info("manual update requested")
	ev := daemon.RunCycle(ctx, cfg, s.factory, s.interval)
	s.onDaemonEvent(ev)
	if ev.Err != nil {
		return ev, ev.Err
	}
	return ev, nil
}

// Record reads the current AAAA record from Cloudflare.
func (s *Service) Record(ctx context.Context) (cloudflare.Record, error) {
	cfg := s.currentConfig()
	_, _, cf := s.factory(cfg)
	if cf == nil {
		return cloudflare.Record{}, errors.New("没有可用的 Cloudflare 客户端")
	}
	return cf.GetRecord(ctx, cfg.ZoneID, cfg.Domain)
}

// InboundResult is the console-facing result of a public inbound check.
type InboundResult struct {
	Reachable bool    `json:"reachable"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
	Target    string  `json:"target"`
	CheckedAt string  `json:"checked_at"`
	NewIP     string  `json:"new_ip,omitempty"`
}

// InboundCheck publishes the current address (when it changed) and asks the
// Cloudflare Worker to connect back to domain:port.
func (s *Service) InboundCheck(ctx context.Context) (InboundResult, error) {
	cfg := s.currentConfig()
	if strings.TrimSpace(cfg.Domain) == "" {
		return InboundResult{}, errors.New("请先在配置页填写域名")
	}
	if cfg.Proxied {
		return InboundResult{}, errors.New("域名开着橙云代理，Worker 会连到 Cloudflare 而不是本机；请改成灰云")
	}
	port := cfg.EffectiveInboundPort()
	if port == cfg.ListenPort {
		if _, err := s.listenerState(); err != nil {
			return InboundResult{}, fmt.Errorf("本机监听没有启动：%w", err)
		}
	}
	if !s.busy.CompareAndSwap(false, true) {
		return InboundResult{}, ErrBusy
	}
	defer s.busy.Store(false)

	_, engine, _ := s.factory(cfg)
	if engine == nil {
		return InboundResult{}, errors.New("没有可用的 DDNS 引擎")
	}
	res, err := engine.RunOnce(ctx)
	if err == nil {
		s.onDaemonEvent(daemon.Event{Result: res})
	}
	if err != nil {
		out := InboundResult{
			Error:     "绑定失败：" + err.Error(),
			Target:    fmt.Sprintf("%s:%d", cfg.Domain, port),
			CheckedAt: time.Now().Format(time.RFC3339),
		}
		s.storeInbound(out)
		return out, nil
	}

	target := fmt.Sprintf("%s:%d", cfg.Domain, port)
	check, checkErr := inbound.NewProber(s.workerURLFor(cfg), nil, cfg.Domain).Check(ctx, port)
	out := InboundResult{
		Target:    target,
		CheckedAt: time.Now().Format(time.RFC3339),
		NewIP:     res.NewIP,
	}
	if checkErr != nil {
		out.Error = "检测失败：" + checkErr.Error()
	} else {
		out.Reachable = check.Reachable
		out.LatencyMS = float64(check.Latency.Milliseconds())
		out.Error = check.Err
	}
	s.storeInbound(out)
	return out, nil
}

func (s *Service) storeInbound(out InboundResult) {
	s.mu.Lock()
	s.lastInbound = &InboundStatus{
		Reachable: out.Reachable,
		LatencyMS: out.LatencyMS,
		Error:     out.Error,
		Target:    out.Target,
		Time:      out.CheckedAt,
	}
	s.mu.Unlock()
}

func (s *Service) workerURLFor(cfg config.Config) string {
	if v := strings.TrimSpace(cfg.InboundWorker); v != "" {
		return v
	}
	return s.worker
}

// ---- configuration --------------------------------------------------------

// SaveConfig validates and persists cfg, then applies the settings that need
// live reconfiguration (interval, listener port, autostart).
func (s *Service) SaveConfig(cfg config.Config, autostartOn bool) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if err := s.store.Save(cfg); err != nil {
		return err
	}

	old := s.currentConfig()
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()

	s.logger.SetSecrets()
	if cfg.APIToken != "" {
		s.logger.AddSecret(cfg.APIToken)
	}
	if d, err := time.ParseDuration(cfg.Interval); err == nil {
		s.mu.Lock()
		s.interval = d
		s.mu.Unlock()
	}
	if cfg.ListenPort != old.ListenPort {
		s.startListener(cfg.ListenPort)
	}

	if s.autoMgr != nil {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("定位可执行文件失败：%w", err)
		}
		if autostartOn {
			if err := s.autoMgr.Enable(exe); err != nil {
				return fmt.Errorf("开启自启动失败：%w", err)
			}
		} else if err := s.autoMgr.Disable(); err != nil {
			return fmt.Errorf("关闭自启动失败：%w", err)
		}
	}
	s.logger.Info("configuration saved", "path", s.store.Path())
	return nil
}

// AutostartEnabled reports the current OS autostart state.
func (s *Service) AutostartEnabled() bool {
	if s.autoMgr == nil {
		return false
	}
	ok, err := s.autoMgr.IsEnabled()
	return err == nil && ok
}

// ---- status ---------------------------------------------------------------

// EventStatus is the console-facing view of the last DDNS cycle.
type EventStatus struct {
	Updated   bool   `json:"updated"`
	OldIP     string `json:"old_ip"`
	NewIP     string `json:"new_ip"`
	Message   string `json:"message"`
	Error     string `json:"error,omitempty"`
	Time      string `json:"time"`
	Running   bool   `json:"running"`
	Addresses int    `json:"address_count"`
}

// RecordStatus is the console-facing view of one configured AAAA record.
type RecordStatus struct {
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Updated bool   `json:"updated"`
	OldIP   string `json:"old_ip"`
	NewIP   string `json:"new_ip"`
	Message string `json:"message"`
	Error   string `json:"error,omitempty"`
}

// AddressStatus is the console-facing view of one local IPv6 address.
type AddressStatus struct {
	IP        string  `json:"ip"`
	Interface string  `json:"interface"`
	Kind      string  `json:"kind"`
	Stable    bool    `json:"stable"`
	Reachable bool    `json:"reachable"`
	LatencyMS float64 `json:"latency_ms"`
	Method    string  `json:"method"`
	Error     string  `json:"error,omitempty"`
}

// ListenerStatus describes the public inbound listener.
type ListenerStatus struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

// InboundStatus is the last public inbound check, kept across page loads.
type InboundStatus struct {
	Reachable bool    `json:"reachable"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
	Target    string  `json:"target"`
	Time      string  `json:"time"`
}

// Status is everything the console's overview and address pages need.
type Status struct {
	Version     string          `json:"version"`
	ConfigPath  string          `json:"config_path"`
	AdminURL    string          `json:"admin_url"`
	Domain      string          `json:"domain"`
	Policy      string          `json:"policy"`
	Interval    string          `json:"interval"`
	ListenPort  int             `json:"listen_port"`
	InboundPort int             `json:"inbound_port"`
	PublishedIP string          `json:"published_ip"`
	Autostart   bool            `json:"autostart"`
	LastEvent   EventStatus     `json:"last_event"`
	Records     []RecordStatus  `json:"records"`
	Addresses   []AddressStatus `json:"addresses"`
	Listener    ListenerStatus  `json:"listener"`
	LastInbound *InboundStatus  `json:"last_inbound,omitempty"`
	LogCursor   int64           `json:"log_cursor"`
}

// Status builds a consistent snapshot of the service state.
func (s *Service) Status() Status {
	cfg := s.currentConfig()
	s.mu.RLock()
	ev := s.lastEvent
	addrs := append([]AddressStatus(nil), s.addrViewsLocked()...)
	inbound := s.lastInbound
	adminURL := s.adminURL
	s.mu.RUnlock()

	records := make([]RecordStatus, 0, len(ev.Result.Records))
	for _, r := range ev.Result.Records {
		records = append(records, RecordStatus{
			Domain:  r.Domain,
			Source:  r.Source,
			Updated: r.Updated,
			OldIP:   r.OldIP,
			NewIP:   r.NewIP,
			Message: r.Message,
			Error:   r.Error,
		})
	}

	st := Status{
		Version:     s.version,
		ConfigPath:  s.store.Path(),
		AdminURL:    adminURL,
		Domain:      cfg.Domain,
		Policy:      string(cfg.Policy),
		Interval:    cfg.Interval,
		ListenPort:  cfg.ListenPort,
		InboundPort: cfg.EffectiveInboundPort(),
		Autostart:   s.AutostartEnabled(),
		Records:     records,
		LastEvent: EventStatus{
			Updated:   ev.Result.Updated,
			OldIP:     ev.Result.OldIP,
			NewIP:     ev.Result.NewIP,
			Message:   ev.Result.Message,
			Time:      formatTime(ev.Result.Timestamp),
			Running:   s.busy.Load(),
			Addresses: len(addrs),
		},
		Addresses: addrs,
	}
	st.PublishedIP = ev.Result.NewIP
	if ev.Err != nil {
		st.LastEvent.Error = ev.Err.Error()
	}
	if ev.Result.Timestamp.IsZero() {
		st.LastEvent.Time = ""
	}
	addr, err := s.listenerState()
	st.Listener = ListenerStatus{Address: addr, Port: cfg.ListenPort, OK: err == nil}
	if err != nil {
		st.Listener.Error = err.Error()
	}
	if inbound != nil {
		cp := *inbound
		st.LastInbound = &cp
	}
	if s.buf != nil {
		st.LogCursor = s.buf.Cursor()
	}
	return st
}

func (s *Service) addrViewsLocked() []AddressStatus {
	out := make([]AddressStatus, 0, len(s.addrs))
	for _, a := range s.addrs {
		out = append(out, AddressStatus{
			IP:        a.IP.String(),
			Interface: a.Interface,
			Kind:      string(a.Kind),
			Stable:    a.Stable,
			Reachable: a.Reachable,
			LatencyMS: float64(a.Latency.Milliseconds()),
			Method:    a.Method,
			Error:     a.Err,
		})
	}
	return out
}

func (s *Service) listenerState() (string, error) {
	s.listenMu.Lock()
	defer s.listenMu.Unlock()
	if s.listener != nil {
		return s.listener.Addr(), nil
	}
	if s.listenErr != nil {
		return "", s.listenErr
	}
	return "", errors.New("监听未启动")
}

// Logs returns entries newer than after plus the cursor to use next.
func (s *Service) Logs(after int64) ([]log.Line, int64) {
	if s.buf == nil {
		return nil, 0
	}
	return s.buf.Since(after)
}

// Logger returns the process logger (used by handlers that need to log).
func (s *Service) Logger() *log.Logger { return s.logger }

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
