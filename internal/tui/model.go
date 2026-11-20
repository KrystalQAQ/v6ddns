// Package tui implements the Bubble Tea interface with five pages:
// Dashboard, Config, IPv6 Check, DDNS and Inbound.
//
// The model talks to the rest of the application only through interfaces
// (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI, config.Loader/Store), so
// every network operation is a tea.Cmd and the UI stays responsive. A
// DepsFactory rebuilds those dependencies whenever the saved configuration
// changes, which means edits made in the Config page take effect immediately.
package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

const maxLogLines = 200

// ConfigStore is the read/write persistence contract used by the TUI.
type ConfigStore interface {
	config.Loader
	config.Store
}

// DepsFactory constructs the network-facing dependencies for a configuration.
type DepsFactory func(config.Config) (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI)

type tab int

const (
	tabDashboard tab = iota
	tabConfig
	tabIPv6
	tabDDNS
	tabInbound
)

var tabNames = [...]string{"Dashboard", "Config", "IPv6 Check", "DDNS", "Inbound"}

type field int

const (
	fieldToken field = iota
	fieldZoneID
	fieldDomain
	fieldTTL
	fieldProxied
	fieldInterface
	fieldInterval
	fieldPolicy
	fieldAddress
	fieldSave
	fieldPort
	fieldCount
)

var fieldLabels = [...]string{
	"API Token", "Zone ID", "域名", "TTL", "Proxied",
	"网卡", "间隔", "策略", "手动 IPv6", "保存", "检测端口",
}

// Messages produced by asynchronous tea.Cmds.
type (
	configMsg struct {
		cfg config.Config
		err error
	}
	detectMsg struct {
		addrs []ipv6.Address
		err   error
	}
	ddnsMsg struct {
		result ddns.Result
		err    error
	}
	cfMsg struct {
		ip  string
		err error
	}
	inboundMsg struct {
		result inbound.Result
		err    error
	}
	logMsg struct{ line string }
)

// LogSink is an io.Writer for log.Logger that forwards complete log lines to
// the TUI as messages. It keeps the logger and the event loop decoupled: the
// program itself never needs to be passed into the model.
type LogSink struct {
	mu   sync.Mutex
	send func(tea.Msg)
}

// NewLogSink creates an empty sink. Call SetSend once the model exists.
func NewLogSink() *LogSink { return &LogSink{} }

// SetSend installs the callback used to deliver log lines to the model.
func (s *LogSink) SetSend(fn func(tea.Msg)) {
	s.mu.Lock()
	s.send = fn
	s.mu.Unlock()
}

// Write implements io.Writer. Write calls from the logger are expected to carry
// one formatted line, but multiple lines are handled defensively.
func (s *LogSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	fn := s.send
	s.mu.Unlock()
	if fn != nil {
		for _, line := range strings.Split(strings.TrimRight(string(p), "\r\n"), "\n") {
			if line != "" {
				fn(logMsg{line: line})
			}
		}
	}
	return len(p), nil
}

// Model is the Bubble Tea model for the whole application.
type Model struct {
	cfg      config.Config
	store    ConfigStore
	factory  DepsFactory
	detector ipv6.Detector
	engine   ddns.Engine
	cf       cloudflare.ClientAPI
	logger   *log.Logger

	// Inbound probing is rebuilt alongside the other network dependencies so a
	// changed API token in Config takes effect on the next check as well.
	prober           inbound.Prober
	newProber        func(cloudflare.ClientAPI) inbound.Prober
	inboundWorkerURL string

	ctx    context.Context
	cancel context.CancelFunc

	width  int
	height int
	active tab

	inputs  []textinput.Model
	focus   field
	proxied bool
	policy  config.TargetPolicy

	message      string
	messageIsErr bool

	msgs     chan tea.Msg
	logLines []string

	lastDetect    []ipv6.Address
	lastDetectErr string
	lastDetectAt  time.Time
	detecting     bool

	lastResult    ddns.Result
	lastResultErr string
	updating      bool

	cfIP  string
	cfErr string

	inboundChecking bool
	inboundResult   inbound.Result
	inboundErr      string
	inboundAt       time.Time
}

// New builds the model. The sink, if provided, is wired to receive log lines.
// proberFactory builds the inbound prober from the current Cloudflare client (so
// a saved API token change also applies to inbound checks); workerURL is only
// used for display.
func New(cfg config.Config, store ConfigStore, factory DepsFactory, logger *log.Logger, sink *LogSink, proberFactory func(cloudflare.ClientAPI) inbound.Prober, workerURL string) *Model {
	ctx, cancel := context.WithCancel(context.Background())
	detector, engine, cf := factory(cfg)
	if workerURL == "" {
		workerURL = inbound.DefaultWorkerURL
	}

	m := &Model{
		cfg:              cfg,
		store:            store,
		factory:          factory,
		detector:         detector,
		engine:           engine,
		cf:               cf,
		logger:           logger,
		newProber:        proberFactory,
		inboundWorkerURL: workerURL,
		ctx:              ctx,
		cancel:           cancel,
		width:            100,
		height:           30,
		msgs:             make(chan tea.Msg, 256),
		logLines:         make([]string, 0, maxLogLines),
	}
	if proberFactory != nil {
		m.prober = proberFactory(cf)
	}
	m.inputs = newInputs()
	m.setForm(cfg)
	m.setFocus(fieldToken)
	if sink != nil {
		sink.SetSend(m.Send)
	}
	return m
}

func newInputs() []textinput.Model {
	makeInput := func(placeholder string) textinput.Model {
		ti := textinput.New()
		ti.Prompt = ""
		ti.CharLimit = 256
		ti.Width = 44
		ti.Placeholder = placeholder
		return ti
	}
	token := makeInput("Cloudflare API Token")
	token.EchoMode = textinput.EchoPassword
	token.EchoCharacter = '•'
	zone := makeInput("Zone ID")
	domain := makeInput("example.com")
	ttl := makeInput("1")
	iface := makeInput("留空=全部网卡")
	interval := makeInput("5m")
	address := makeInput("2408:... (仅手动策略)")
	port := makeInput("38080")
	port.CharLimit = 5
	return []textinput.Model{token, zone, domain, ttl, iface, interval, address, port}
}

// inputFor maps a form field to its textinput index.
func (m *Model) inputFor(f field) (int, bool) {
	switch f {
	case fieldToken:
		return 0, true
	case fieldZoneID:
		return 1, true
	case fieldDomain:
		return 2, true
	case fieldTTL:
		return 3, true
	case fieldInterface:
		return 4, true
	case fieldInterval:
		return 5, true
	case fieldAddress:
		return 6, true
	case fieldPort:
		return 7, true
	default:
		return 0, false
	}
}

func (m *Model) setForm(cfg config.Config) {
	m.inputs[0].SetValue(cfg.APIToken)
	m.inputs[1].SetValue(cfg.ZoneID)
	m.inputs[2].SetValue(cfg.Domain)
	m.inputs[3].SetValue(strconv.Itoa(cfg.TTL))
	m.inputs[4].SetValue(cfg.InterfaceName)
	m.inputs[5].SetValue(cfg.Interval)
	m.inputs[6].SetValue(cfg.Address)
	if m.inputs[7].Value() == "" {
		m.inputs[7].SetValue("38080")
	}
	m.proxied = cfg.Proxied
	m.policy = cfg.Policy
}

func (m *Model) setFocus(f field) {
	for i := range m.inputs {
		m.inputs[i].Blur()
	}
	m.focus = f
	if idx, ok := m.inputFor(f); ok {
		m.inputs[idx].Focus()
	}
}

func (m *Model) moveFocus(delta int) {
	next := (int(m.focus) + delta + int(fieldCount)) % int(fieldCount)
	m.setFocus(field(next))
}

func (m *Model) setTab(t tab) {
	if t < 0 {
		t = tabInbound
	}
	if t > tabInbound {
		t = tabDashboard
	}
	if t != m.active {
		m.active = t
		m.message, m.messageIsErr = "", false
	}
}

func (m *Model) setMessage(s string) {
	m.message, m.messageIsErr = s, false
}

func (m *Model) setError(err error) {
	m.message, m.messageIsErr = err.Error(), true
}

// Send delivers a message to the model without ever blocking the logger.
func (m *Model) Send(msg tea.Msg) {
	select {
	case m.msgs <- msg:
	default:
	}
}

func (m *Model) nextInternalMsg() tea.Cmd {
	return func() tea.Msg { return <-m.msgs }
}

func (m *Model) appendLog(line string) {
	if len(m.logLines) >= maxLogLines {
		m.logLines = append(m.logLines[:0], m.logLines[len(m.logLines)-maxLogLines+1:]...)
	}
	m.logLines = append(m.logLines, line)
}

func (m *Model) rebuildDeps() {
	m.detector, m.engine, m.cf = m.factory(m.cfg)
	if m.newProber != nil {
		m.prober = m.newProber(m.cf)
	}
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.nextInternalMsg()}
	if m.store != nil {
		cmds = append(cmds, m.reloadConfigCmd())
	}
	return tea.Batch(cmds...)
}

func (m *Model) reloadConfigCmd() tea.Cmd {
	store := m.store
	if store == nil {
		return nil
	}
	return func() tea.Msg {
		cfg, err := store.Load()
		return configMsg{cfg: cfg, err: err}
	}
}

func (m *Model) refreshCF() tea.Cmd {
	if m.cf == nil || m.cfg.ZoneID == "" || m.cfg.Domain == "" {
		return nil
	}
	cf, zone, domain, ctx := m.cf, m.cfg.ZoneID, m.cfg.Domain, m.ctx
	return func() tea.Msg {
		c, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		rec, err := cf.GetRecord(c, zone, domain)
		if err != nil {
			if errors.Is(err, cloudflare.ErrRecordNotFound) {
				return cfMsg{ip: "（尚无 AAAA 记录）"}
			}
			return cfMsg{err: err}
		}
		return cfMsg{ip: displayIP(rec.Content)}
	}
}

func (m *Model) startDetect() tea.Cmd {
	if m.detector == nil {
		m.setError(errors.New("未配置 IPv6 检测器"))
		return nil
	}
	m.detecting = true
	m.lastDetectErr = ""
	detector, ctx := m.detector, m.ctx
	return func() tea.Msg {
		c, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		addrs, err := detector.Detect(c)
		return detectMsg{addrs: addrs, err: err}
	}
}

func (m *Model) startUpdate() tea.Cmd {
	if m.engine == nil {
		m.setError(errors.New("未配置 DDNS 引擎"))
		return nil
	}
	m.updating = true
	m.lastResultErr = ""
	engine, ctx := m.engine, m.ctx
	return func() tea.Msg {
		c, cancel := context.WithTimeout(ctx, 90*time.Second)
		defer cancel()
		res, err := engine.RunOnce(c)
		return ddnsMsg{result: res, err: err}
	}
}

// startInbound kicks off an asynchronous edge probe. It reuses the DDNS
// candidate address if one is available; otherwise the user can set the target
// via the manual policy/address in Config.
func (m *Model) startInbound() tea.Cmd {
	if m.prober == nil {
		m.setError(errors.New("未配置入站检测器"))
		return nil
	}
	ip, _ := m.candidate()
	if ip == "" || ip == "-" {
		m.setError(errors.New("没有可用的候选 IPv6，请先按 c 检测或配置手动地址"))
		return nil
	}
	port, err := strconv.Atoi(strings.TrimSpace(m.inputs[7].Value()))
	if err != nil || port < 1 || port > 65535 || port == 25 {
		m.setError(fmt.Errorf("端口必须是 1-65535 且不能是 25"))
		return nil
	}
	m.inboundChecking = true
	m.inboundErr = ""
	prober, ctx := m.prober, m.ctx
	return func() tea.Msg {
		c, cancel := context.WithTimeout(ctx, 40*time.Second)
		defer cancel()
		res, err := prober.Check(c, ip, port)
		return inboundMsg{result: res, err: err}
	}
}

func (m *Model) refresh() tea.Cmd {
	switch m.active {
	case tabConfig:
		return m.reloadConfigCmd()
	case tabIPv6:
		return m.startDetect()
	case tabDDNS:
		return m.refreshCF()
	case tabInbound:
		return m.startInbound()
	default:
		return tea.Batch(m.reloadConfigCmd(), m.refreshCF())
	}
}

func (m *Model) saveConfig() tea.Cmd {
	cfg := m.cfg
	cfg.APIToken = m.inputs[0].Value()
	cfg.ZoneID = strings.TrimSpace(m.inputs[1].Value())
	cfg.Domain = strings.TrimSpace(m.inputs[2].Value())
	ttl, err := strconv.Atoi(strings.TrimSpace(m.inputs[3].Value()))
	if err != nil {
		m.setError(fmt.Errorf("TTL 必须是数字: %w", err))
		return nil
	}
	cfg.TTL = ttl
	cfg.InterfaceName = strings.TrimSpace(m.inputs[4].Value())
	cfg.Interval = strings.TrimSpace(m.inputs[5].Value())
	cfg.Address = strings.TrimSpace(m.inputs[6].Value())
	cfg.Proxied = m.proxied
	cfg.Policy = m.policy

	if err := cfg.Validate(); err != nil {
		m.setError(err)
		return nil
	}
	if m.store == nil {
		m.setError(errors.New("没有可用的配置存储"))
		return nil
	}
	if err := m.store.Save(cfg); err != nil {
		m.setError(err)
		return nil
	}
	m.cfg = cfg
	if m.logger != nil {
		m.logger.SetSecrets(cfg.APIToken)
	}
	m.rebuildDeps()
	m.setMessage("配置已保存: " + m.store.Path())
	return m.refreshCF()
}

func (m *Model) toggleFocused() {
	switch m.focus {
	case fieldProxied:
		m.proxied = !m.proxied
	case fieldPolicy:
		policies := []config.TargetPolicy{
			config.PolicyStableAuto,
			config.PolicyAnyReachable,
			config.PolicyManual,
		}
		for i, p := range policies {
			if p == m.policy {
				m.policy = policies[(i+1)%len(policies)]
				return
			}
		}
		m.policy = policies[0]
	}
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height

	case logMsg:
		m.appendLog(msg.line)
		cmds = append(cmds, m.nextInternalMsg())

	case configMsg:
		if msg.err != nil {
			m.setError(msg.err)
			break
		}
		m.cfg = msg.cfg
		m.rebuildDeps()
		m.setForm(msg.cfg)
		if m.logger != nil {
			m.logger.SetSecrets(msg.cfg.APIToken)
		}
		cmds = append(cmds, m.refreshCF())

	case detectMsg:
		m.detecting = false
		m.lastDetectAt = time.Now()
		if msg.err != nil {
			m.lastDetectErr = msg.err.Error()
		} else {
			m.lastDetect = msg.addrs
		}

	case ddnsMsg:
		m.updating = false
		m.lastResult = msg.result
		m.lastResultErr = ""
		if msg.err != nil {
			m.lastResultErr = msg.err.Error()
		}
		cmds = append(cmds, m.refreshCF())
		if msg.err == nil && m.detector != nil {
			cmds = append(cmds, m.startDetect())
		}

	case cfMsg:
		m.cfIP, m.cfErr = msg.ip, ""
		if msg.err != nil {
			m.cfErr = msg.err.Error()
		}

	case inboundMsg:
		m.inboundChecking = false
		m.inboundAt = time.Now()
		m.inboundResult = msg.result
		m.inboundErr = ""
		if msg.err != nil {
			m.inboundErr = msg.err.Error()
		}

	case tea.KeyMsg:
		if cmd := m.handleKey(msg); cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	if len(cmds) == 0 {
		return m, nil
	}
	return m, tea.Batch(cmds...)
}

func (m *Model) handleKey(msg tea.KeyMsg) tea.Cmd {
	s := msg.String()
	if s == "ctrl+c" {
		m.cancel()
		return tea.Quit
	}
	if m.active == tabConfig {
		return m.handleConfigKey(msg)
	}
	if m.active == tabInbound {
		// Only the port field is editable here. While focused, feed every key
		// to the input except explicit navigation/shortcut keys.
		switch s {
		case "tab", "shift+tab":
			if m.focus == fieldPort {
				m.setFocus(field(-1))
			} else {
				m.setFocus(fieldPort)
			}
			return nil
		case "esc":
			m.setFocus(field(-1))
			m.setTab(tabDashboard)
			return nil
		case "i", "r", "q", "ctrl+c":
			// handled by the global switch below
		default:
			if m.focus == fieldPort {
				var cmd tea.Cmd
				m.inputs[7], cmd = m.inputs[7].Update(msg)
				return cmd
			}
		}
	}
	switch s {
	case "q":
		m.cancel()
		return tea.Quit
	case "tab":
		m.setTab(m.active + 1)
	case "shift+tab":
		m.setTab(m.active - 1)
	case "esc":
		m.setTab(tabDashboard)
	case "1", "2", "3", "4", "5":
		m.setTab(tab(int(s[0] - '1')))
	case "i":
		if m.active == tabInbound {
			return m.startInbound()
		}
		m.setTab(tabInbound)
	case "c":
		return m.startDetect()
	case "u":
		return m.startUpdate()
	case "r":
		return m.refresh()
	}
	return nil
}

func (m *Model) handleConfigKey(msg tea.KeyMsg) tea.Cmd {
	s := msg.String()
	switch s {
	case "esc":
		m.setForm(m.cfg)
		m.setFocus(fieldToken)
		m.setTab(tabDashboard)
		m.setMessage("已放弃未保存的修改")
		return nil
	case "tab":
		m.moveFocus(1)
		return nil
	case "shift+tab":
		m.moveFocus(-1)
		return nil
	case "enter":
		if m.focus == fieldSave {
			return m.saveConfig()
		}
		m.moveFocus(1)
		return nil
	case "ctrl+s":
		return m.saveConfig()
	case " ":
		m.toggleFocused()
		return nil
	case "left", "right":
		if m.focus == fieldProxied || m.focus == fieldPolicy {
			m.toggleFocused()
			return nil
		}
	}
	if idx, ok := m.inputFor(m.focus); ok {
		var cmd tea.Cmd
		m.inputs[idx], cmd = m.inputs[idx].Update(msg)
		return cmd
	}
	return nil
}

// candidate returns the IPv6 address the DDNS engine is most likely to pick,
// together with a short description of where it came from.
func (m *Model) candidate() (string, string) {
	if m.cfg.Policy == config.PolicyManual {
		return displayIP(m.cfg.Address), "手动指定"
	}
	for i := range m.lastDetect {
		a := m.lastDetect[i]
		if a.Kind != ipv6.KindGUA || !a.Reachable {
			continue
		}
		if m.cfg.Policy == config.PolicyStableAuto && !a.Stable {
			continue
		}
		source := a.Interface + " / " + shortMethod(a.Method)
		if a.Stable {
			source += " / stable"
		} else {
			source += " / temporary"
		}
		return a.IP.String(), source
	}
	return "", ""
}

func displayIP(s string) string {
	if s == "" {
		return "-"
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return s
	}
	return ip.String()
}

func shortMethod(method string) string {
	switch method {
	case ipv6.ProbeMethodICMP:
		return "icmp"
	case ipv6.ProbeMethodTCP:
		return "tcp"
	default:
		return method
	}
}

// View implements tea.Model. The concrete page renderers live in views.go.
func (m *Model) View() string {
	if m.width < 40 {
		return "终端窗口太窄，请调宽后重试。"
	}
	header := m.headerView()
	footer := m.helpView()
	contentH := m.height - lipgloss.Height(header) - lipgloss.Height(footer) - 2
	if contentH < 6 {
		contentH = 6
	}
	var body string
	switch m.active {
	case tabConfig:
		body = m.configView()
	case tabIPv6:
		body = m.ipv6View()
	case tabDDNS:
		body = m.ddnsView()
	case tabInbound:
		body = m.inboundView()
	default:
		body = m.dashboardView(contentH)
	}
	lines := strings.Split(body, "\n")
	if len(lines) > contentH {
		lines = lines[:contentH]
	}
	for len(lines) < contentH {
		lines = append(lines, "")
	}
	return strings.Join([]string{header, strings.Join(lines, "\n"), footer}, "\n")
}
