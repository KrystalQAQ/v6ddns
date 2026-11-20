// Command v6ddns is a Cloudflare IPv6 DDNS daemon with an interactive TUI.
//
// Usage:
//
//	v6ddns                 # interactive TUI (default)
//	v6ddns --daemon        # run continuously at the configured interval
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
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
	"github.com/KrystalQAQ/v6ddns/internal/tui"
)

func main() {
	var (
		daemon        = flag.Bool("daemon", false, "run in the background without a TUI")
		once          = flag.Bool("once", false, "detect and update once, then exit")
		configPath    = flag.String("config", "", "path to the configuration file")
		icmp          = flag.Bool("icmp", false, "also try ICMPv6 probes (needs raw-socket privileges)")
		inboundWorker = flag.String("inbound-worker", inbound.DefaultWorkerURL, "inbound probe Worker URL")
	)
	flag.Parse()

	if *daemon && *once {
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

	// Network dependencies are rebuilt from the latest config on every cycle in
	// daemon mode and whenever the TUI's config page is saved.
	newDeps := func(c config.Config) (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI) {
		localOpts := []ipv6.Option{}
		if *icmp {
			localOpts = append(localOpts, ipv6.WithICMP(true))
		}
		if c.InterfaceName != "" {
			localOpts = append(localOpts, ipv6.WithInterface(c.InterfaceName))
		}
		if len(c.ProbeTargets) > 0 {
			localOpts = append(localOpts, ipv6.WithProbeTargets(c.ProbeTargetsToUse()...))
		}
		if t, err := time.ParseDuration(c.ProbeTimeout); err == nil {
			localOpts = append(localOpts, ipv6.WithTimeout(t))
		}
		detector := ipv6.NewDetector(localOpts...)
		cf := cloudflare.NewClient(c.APIToken, cloudflare.DefaultTimeout)
		engine := ddns.NewEngine(c, detector, cf, log.Default)
		return detector, engine, cf
	}

	switch {
	case *once:
		logToStdout()
		if err := runOnce(ctx, cfg, newDeps, interval); err != nil {
			os.Exit(1)
		}
	case *daemon:
		logToStdout()
		runDaemon(ctx, cfg, store, newDeps, interval)
	default:
		runTUI(cfg, store, newDeps, *inboundWorker)
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

// logToStdout switches the package-level logger to stdout for non-interactive
// modes, without touching stderr used by flag parsing errors.
func logToStdout() {
	log.Default = log.New(os.Stdout, log.LevelInfo)
}

// runOnce performs one detection + DDNS cycle and prints the result.
func runOnce(ctx context.Context, cfg config.Config, factory tui.DepsFactory, timeout time.Duration) error {
	_, engine, _ := factory(cfg)
	c, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()
	result, err := engine.RunOnce(c)
	if err != nil {
		log.Error("once: update failed", "error", err)
		return err
	}
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}
	fmt.Printf("time=%s updated=%t old=%s new=%s message=%q\n",
		result.Timestamp.Format(time.RFC3339), result.Updated,
		valueOrDash(result.OldIP), valueOrDash(result.NewIP), result.Message)
	return nil
}

// runDaemon loops until ctx is cancelled, reloading the config every cycle.
func runDaemon(ctx context.Context, cfg config.Config, store tui.ConfigStore, factory tui.DepsFactory, interval time.Duration) {
	log.Info("daemon started", "interval", interval.String(), "config", store.Path())
	defer log.Info("daemon stopped")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		if err := runCycle(ctx, cfg, factory, interval); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Error("cycle failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := store.Load()
			if err != nil {
				log.Error("reload config failed", "error", err)
				continue
			}
			cfg = current
			if d, err := time.ParseDuration(cfg.Interval); err == nil && d != interval {
				interval = d
				ticker.Reset(interval)
				log.Info("interval changed", "interval", interval.String())
			}
		}
	}
}

func runCycle(ctx context.Context, cfg config.Config, factory tui.DepsFactory, timeout time.Duration) error {
	detector, engine, _ := factory(cfg)
	c, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	addrs, err := detector.Detect(c)
	if err != nil {
		return fmt.Errorf("detect IPv6: %w", err)
	}
	for _, a := range addrs {
		log.Debug("address", "ip", a.IP.String(), "interface", a.Interface,
			"kind", string(a.Kind), "stable", a.Stable, "reachable", a.Reachable,
			"method", a.Method, "latency", a.Latency.String())
	}
	result, err := engine.RunOnce(c)
	if err != nil {
		return err
	}
	log.Info("ddns result", "updated", result.Updated, "old", result.OldIP,
		"new", result.NewIP, "message", result.Message)
	return nil
}

func runTUI(cfg config.Config, store tui.ConfigStore, factory tui.DepsFactory, workerURL string) {
	sink := tui.NewLogSink()
	logger := log.New(sink, log.LevelInfo)
	if cfg.APIToken != "" {
		logger.AddSecret(cfg.APIToken)
	}
	log.Default = logger

	// The inbound prober shares the Cloudflare client from the factory. It is
	// rebuilt whenever the config is reloaded via newProber, so saved token
	// changes take effect on the next edge probe.
	newProber := func(cf cloudflare.ClientAPI) inbound.Prober {
		return inbound.NewProber(workerURL, nil, cf, inbound.ZoneID, inbound.TargetRecordID)
	}
	model := tui.New(cfg, store, factory, logger, sink, newProber, workerURL)
	p := tea.NewProgram(model, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "TUI error:", err)
		os.Exit(1)
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
