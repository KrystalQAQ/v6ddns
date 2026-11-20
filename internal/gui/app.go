// Package gui implements the Fyne desktop frontend. Long-running network
// calls happen in goroutines; every widget mutation is marshalled through
// fyne.Do so it runs on Fyne's event goroutine.
package gui

import (
	"context"
	_ "embed"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
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

	// Widgets the daemon event stream needs to refresh.
	logView    *widget.Entry
	statusIP   *widget.Label
	statusTime *widget.Label
	statusMsg  *widget.Label
	ipTable    *widget.Table
	cfIP       *widget.Label
	inResult   *widget.Label
	trayMenu   *fyne.Menu
}

// Run constructs and runs the GUI (blocking until the app exits).
func Run(opts Options) error {
	interval, err := time.ParseDuration(opts.Config.Interval)
	if err != nil {
		return fmt.Errorf("invalid interval: %w", err)
	}
	a := app.NewWithID("com.krystalqaq.v6ddns")
	a.SetIcon(trayIcon)
	w := a.NewWindow("v6ddns — Cloudflare IPv6 DDNS")
	w.Resize(fyne.NewSize(960, 680))
	w.SetIcon(trayIcon)

	g := &App{
		fyneApp:  a,
		window:   w,
		opts:     opts,
		cfg:      opts.Config,
		interval: interval,
		autoMgr:  autostart.New(),
	}

	pages := g.buildPages()
	tabs := container.NewAppTabs(pages...)
	w.SetContent(tabs)
	w.SetCloseIntercept(func() { w.Hide() }) // close == hide to tray
	g.setupTray()

	// Route the package logger into the dashboard log view.
	logger := log.New(&guiLogWriter{g: g}, log.LevelInfo)
	if g.cfg.APIToken != "" {
		logger.AddSecret(g.cfg.APIToken)
	}
	log.Default = logger

	// Start the background DDNS loop. GUI + GUI never run two loops: the only
	// other loop is the CLI --daemon mode, which is a separate process.
	go daemon.RunLoop(context.Background(), g.cfg, opts.Store, opts.Factory, interval, g.onDaemonEvent)

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

func (g *App) newProber(cf cloudflare.ClientAPI) inbound.Prober {
	return inbound.NewProber(g.opts.WorkerURL, nil, cf, inbound.ZoneID, inbound.TargetRecordID)
}
