// Package gui implements the Fyne desktop frontend. Long-running network
// calls happen in goroutines; every widget mutation is marshalled through
// fyne.Do so it runs on Fyne's event goroutine.
package gui

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/KrystalQAQ/v6ddns/internal/autostart"
	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

//go:embed assets/icon.png
var iconBytes []byte

var trayIcon = fyne.NewStaticResource("icon.png", iconBytes)

// Options is everything main.go needs to hand the GUI.
type Options struct {
	Config      config.Config
	Store       daemon.ConfigStore
	Factory     daemon.DepsFactory
	WorkerURL   string
	StartHidden bool
	ICMP        bool
	Cancel      context.CancelFunc
	OnQuit      func()
}

// App owns the Fyne application and all UI state.
type App struct {
	fyneApp fyne.App
	window  fyne.Window
	opts    Options

	mu        sync.RWMutex
	cfg       config.Config
	lastEvent daemon.Event
	addrs     []ipv6.Address

	autoMgr     autostart.Manager
	interval    time.Duration
	manualRun   atomic.Bool
	lastNotify  time.Time
	notifyMutex sync.Mutex

	// Inbound listener state (the tiny HTTP server exposed while the app runs).
	listenMu  sync.Mutex
	listener  *inbound.Server
	listenErr error

	// Navigation.
	pages      []fyne.CanvasObject
	navButtons []*widget.Button

	// Widgets the daemon event stream and pages need to refresh.
	logView     *widget.Entry
	statusIP    *widget.Label
	statusTime  *widget.Label
	statusMsg   *widget.Label
	statusDot   *canvas.Circle
	ipTable     *widget.Table
	ipCount     *widget.Label
	cfIP        *widget.Label
	cfState     *widget.Label
	ddnsDomain  *widget.Label
	ddnsLocalIP *widget.Label
	inResult    *widget.Label
	inResultDot *canvas.Circle
	inListen    *widget.Label
	inListenDot *canvas.Circle
	inDomain    *widget.Label
	inPort      *widget.Label
	trayMenu    *fyne.Menu
}

// Run constructs and runs the GUI (blocking until the app exits).
func Run(opts Options) error {
	interval, err := time.ParseDuration(opts.Config.Interval)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}
	a := app.NewWithID("com.krystalqaq.v6ddns")
	a.Settings().SetTheme(newAppTheme())
	a.SetIcon(trayIcon)
	w := a.NewWindow("v6ddns — Cloudflare IPv6 DDNS")
	w.Resize(fyne.NewSize(1000, 720))
	w.SetIcon(trayIcon)

	g := &App{
		fyneApp:  a,
		window:   w,
		opts:     opts,
		cfg:      opts.Config,
		interval: interval,
		autoMgr:  autostart.New(),
	}

	w.SetContent(g.buildShell())
	w.SetCloseIntercept(func() { w.Hide() }) // close == hide to tray
	g.setupTray()

	// Route the package logger into the dashboard log view.
	logger := log.New(&guiLogWriter{g: g}, log.LevelInfo)
	if g.cfg.APIToken != "" {
		logger.AddSecret(g.cfg.APIToken)
	}
	log.Default = logger

	// The app listens as soon as it starts; the inbound check reuses this port.
	g.startListener(opts.Config.ListenPort)
	defer g.stopListener()

	// Start the background DDNS loop. GUI + GUI never run two loops: the only
	// other loop is the CLI --daemon mode, which is a separate process.
	go daemon.RunLoop(context.Background(), g.cfg, opts.Store, opts.Factory, interval, g.onDaemonEvent)

	// Populate the record cards immediately instead of waiting for a manual
	// refresh.
	g.refreshDashboard()

	if opts.StartHidden {
		// A hidden window alone is not enough to keep the app alive on macOS;
		// show once on start and hide immediately.
		a.Lifecycle().SetOnStarted(func() {
			fyne.Do(func() {
				w.Show()
				w.Hide()
			})
		})
		a.Run()
	} else {
		w.ShowAndRun()
	}
	if opts.OnQuit != nil {
		opts.OnQuit()
	}
	return nil
}

func (g *App) currentConfig() config.Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.cfg
}

func (g *App) deps() (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI) {
	return g.opts.Factory(g.currentConfig())
}

// workerURL resolves the inbound probe Worker: an explicit config value wins,
// otherwise the --inbound-worker flag / built-in default is used.
func (g *App) workerURL(cfg config.Config) string {
	if v := strings.TrimSpace(cfg.InboundWorker); v != "" {
		return v
	}
	return g.opts.WorkerURL
}

// startListener (re)binds the inbound HTTP port. It must be called on the UI
// goroutine because it refreshes widgets.
func (g *App) startListener(port int) {
	g.listenMu.Lock()
	old := g.listener
	g.listener = nil
	g.listenErr = nil
	g.listenMu.Unlock()
	if old != nil {
		_ = old.Close()
	}

	srv, err := inbound.StartServer(port)
	g.listenMu.Lock()
	g.listener, g.listenErr = srv, err
	g.listenMu.Unlock()
	if err != nil {
		log.Error("inbound listener failed", "port", port, "error", err)
	} else {
		log.Info("inbound listener started", "addr", srv.Addr())
	}
	g.updateInboundView()
}

func (g *App) stopListener() {
	g.listenMu.Lock()
	srv := g.listener
	g.listener = nil
	g.listenMu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (g *App) listenerState() (string, error) {
	g.listenMu.Lock()
	defer g.listenMu.Unlock()
	if g.listener != nil {
		return g.listener.Addr(), nil
	}
	if g.listenErr != nil {
		return "", g.listenErr
	}
	return "", fmt.Errorf("监听未启动")
}

func (g *App) updateInboundView() {
	cfg := g.currentConfig()
	addr, err := g.listenerState()
	if g.inListen != nil {
		if err != nil {
			g.inListen.SetText("监听失败：" + err.Error())
			setDot(g.inListenDot, errorColor())
		} else {
			g.inListen.SetText("监听中  " + addr)
			setDot(g.inListenDot, successColor())
		}
	}
	if g.inDomain != nil {
		if strings.TrimSpace(cfg.Domain) == "" {
			g.inDomain.SetText("未配置（去「配置」页填写）")
		} else {
			g.inDomain.SetText(cfg.Domain)
		}
	}
	if g.inPort != nil {
		g.inPort.SetText(strconv.Itoa(cfg.ListenPort))
	}
}

// buildShell creates the sidebar + page stack that replaces the old tab bar.
func (g *App) buildShell() fyne.CanvasObject {
	raw := []fyne.CanvasObject{
		g.dashboardPage(),
		g.configPage(),
		g.ipv6Page(),
		g.ddnsPage(),
		g.inboundPage(),
	}
	g.pages = make([]fyne.CanvasObject, len(raw))
	for i, p := range raw {
		g.pages[i] = container.NewPadded(p)
	}
	content := container.NewStack(g.pages...)
	for i, p := range g.pages {
		if i == 0 {
			p.Show()
		} else {
			p.Hide()
		}
	}

	logo := canvas.NewImageFromResource(trayIcon)
	logo.FillMode = canvas.ImageFillContain
	brand := widget.NewLabelWithStyle("v6ddns", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	brandRow := container.NewHBox(container.NewGridWrap(fyne.NewSize(34, 34), logo), brand)
	tagline := mutedText("Cloudflare · IPv6 DDNS")
	header := container.NewVBox(brandRow, tagline)

	items := []struct {
		title string
		icon  fyne.Resource
	}{
		{"总览", theme.HomeIcon()},
		{"配置", theme.SettingsIcon()},
		{"IPv6 地址", theme.ComputerIcon()},
		{"DDNS", theme.UploadIcon()},
		{"入站检测", theme.DownloadIcon()},
	}
	nav := container.NewVBox()
	for i := range items {
		idx := i
		btn := widget.NewButtonWithIcon(items[i].title, items[i].icon, func() { g.showPage(idx) })
		btn.Alignment = widget.ButtonAlignLeading
		btn.Importance = widget.LowImportance
		g.navButtons = append(g.navButtons, btn)
		nav.Add(container.NewGridWrap(fyne.NewSize(206, 42), btn))
	}

	footer := mutedText("自动更新 · 端口监听 · 托盘常驻")
	side := container.NewBorder(header, container.NewPadded(footer), nil, nil, container.NewVScroll(nav))
	background := canvas.NewRectangle(uiColor(theme.ColorNameMenuBackground))
	sidebar := container.NewStack(background, container.NewPadded(side))

	split := container.NewHSplit(sidebar, content)
	split.SetOffset(0.235)
	g.showPage(0)
	return split
}

func (g *App) showPage(idx int) {
	for i, p := range g.pages {
		if i == idx {
			p.Show()
		} else {
			p.Hide()
		}
	}
	for i, b := range g.navButtons {
		if i == idx {
			b.Importance = widget.HighImportance
		} else {
			b.Importance = widget.LowImportance
		}
		b.Refresh()
	}
}
