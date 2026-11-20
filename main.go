// Command v6ddns is a Cloudflare IPv6 DDNS tool with a Fyne GUI and tray icon.
//
// Usage:
//
//	v6ddns                 # open the GUI window
//	v6ddns --tray          # start hidden in the tray (used by autostart)
//	v6ddns --daemon        # run continuously without a GUI (cron/systemd)
//	v6ddns --once          # detect and update once, then exit
//	v6ddns --config PATH   # use a specific config file
//	v6ddns --icmp          # additionally try privileged ICMPv6 probes
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/gui"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

func main() {
	var (
		daemonMode    = flag.Bool("daemon", false, "run in the background without a GUI")
		once          = flag.Bool("once", false, "detect and update once, then exit")
		tray          = flag.Bool("tray", false, "start hidden in the system tray")
		configPath    = flag.String("config", "", "path to the configuration file")
		icmp          = flag.Bool("icmp", false, "also try ICMPv6 probes (needs raw-socket privileges)")
		inboundWorker = flag.String("inbound-worker", inbound.DefaultWorkerURL, "inbound probe Worker URL")
	)
	flag.Parse()

	if *daemonMode && *once {
		fmt.Fprintln(os.Stderr, "--daemon and --once are mutually exclusive")
		os.Exit(2)
	}

	store := newStore(*configPath)
	cfg, err := store.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load config:", err)
		os.Exit(1)
	}
	if cfg.APIToken != "" {
		log.Default.AddSecret(cfg.APIToken)
	}

	interval, err := time.ParseDuration(cfg.Interval)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid interval in config:", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Dependencies are rebuilt from the latest config on every daemon cycle
	// and whenever the GUI config page is saved.
	factory := func(c config.Config) (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI) {
		var opts []ipv6.Option
		if *icmp {
			opts = append(opts, ipv6.WithICMP(true))
		}
		if c.InterfaceName != "" {
			opts = append(opts, ipv6.WithInterface(c.InterfaceName))
		}
		if len(c.ProbeTargets) > 0 {
			opts = append(opts, ipv6.WithProbeTargets(c.ProbeTargetsToUse()...))
		}
		if t, err := time.ParseDuration(c.ProbeTimeout); err == nil {
			opts = append(opts, ipv6.WithTimeout(t))
		}
		detector := ipv6.NewDetector(opts...)
		cf := cloudflare.NewClient(c.APIToken, cloudflare.DefaultTimeout)
		eng := ddns.NewEngine(c, detector, cf, log.Default)
		if c.RequireInbound {
			worker := strings.TrimSpace(c.InboundWorker)
			if worker == "" {
				worker = strings.TrimSpace(*inboundWorker)
			}
			eng.SetInboundProber(inbound.NewProber(worker, nil, c.Domain))
		}
		return detector, eng, cf
	}

	switch {
	case *once:
		logToStdout()
		if srv := startGateListener(cfg); srv != nil {
			defer srv.Close()
		}
		if err := runOnce(ctx, cfg, factory, interval); err != nil {
			os.Exit(1)
		}
	case *daemonMode:
		logToStdout()
		if srv := startGateListener(cfg); srv != nil {
			defer srv.Close()
		}
		daemon.RunLoop(ctx, cfg, store, factory, interval, nil)
	default:
		_, guiCancel := context.WithCancel(ctx)
		defer guiCancel()
		if err := gui.Run(gui.Options{
			Config:      cfg,
			Store:       store,
			Factory:     factory,
			WorkerURL:   *inboundWorker,
			StartHidden: *tray,
			Cancel:      guiCancel,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "GUI error:", err)
			os.Exit(1)
		}
	}
}

func newStore(path string) *config.FileStore {
	if path != "" {
		return config.NewFileStoreWithPath(path)
	}
	s, err := config.NewFileStore()
	if err != nil {
		fmt.Fprintln(os.Stderr, "locate config directory:", err)
		os.Exit(1)
	}
	return s
}

func logToStdout() {
	log.Default = log.New(os.Stdout, log.LevelInfo)
}

// startGateListener opens the app's built-in status listener when the inbound
// gate relies on it (no explicit inbound_port). CLI modes otherwise have no
// listener of their own, so a gate on listen_port would always fail.
func startGateListener(cfg config.Config) *inbound.Server {
	if !cfg.RequireInbound || cfg.InboundPort != 0 {
		return nil
	}
	srv, err := inbound.StartServer(cfg.ListenPort)
	if err != nil {
		log.Warn("inbound gate listener not started; assuming the port is served externally",
			"port", cfg.ListenPort, "error", err)
		return nil
	}
	log.Info("inbound gate listener started", "addr", srv.Addr())
	return srv
}

func runOnce(ctx context.Context, cfg config.Config, factory daemon.DepsFactory, timeout time.Duration) error {
	ev := daemon.RunCycle(ctx, cfg, factory, timeout)
	if ev.Err != nil {
		log.Error("once: update failed", "error", ev.Err)
		return ev.Err
	}
	r := ev.Result
	fmt.Printf("time=%s updated=%t old=%s new=%s message=%q\n",
		r.Timestamp.Format(time.RFC3339), r.Updated,
		valueOrDash(r.OldIP), valueOrDash(r.NewIP), r.Message)
	return nil
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
