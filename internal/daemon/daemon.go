// Package daemon owns the shared DDNS scheduling loop used by both the CLI
// modes and the GUI. Keeping it out of main.go and the (now removed) TUI means
// there is exactly one place responsible for reload-on-tick and timeouts.
package daemon

import (
	"context"
	"fmt"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

// ConfigStore is the read/write persistence contract.
type ConfigStore interface {
	config.Loader
	config.Store
}

// DepsFactory constructs the network-facing dependencies for a configuration.
type DepsFactory func(config.Config) (ipv6.Detector, ddns.Engine, cloudflare.ClientAPI)

// Event describes one completed cycle. The GUI subscribes to these to update
// its dashboard and tray without running a second loop.
type Event struct {
	Addrs  []ipv6.Address
	Result ddns.Result
	Err    error
}

// RunCycle performs one detection + DDNS update with the configured timeout.
func RunCycle(ctx context.Context, cfg config.Config, factory DepsFactory, timeout time.Duration) Event {
	detector, engine, _ := factory(cfg)
	c, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
	defer cancel()

	addrs, err := detector.Detect(c)
	if err != nil {
		return Event{Addrs: addrs, Err: fmt.Errorf("detect IPv6: %w", err)}
	}
	for _, a := range addrs {
		log.Debug("address", "ip", a.IP.String(), "interface", a.Interface,
			"kind", string(a.Kind), "stable", a.Stable, "reachable", a.Reachable,
			"method", a.Method, "latency", a.Latency.String())
	}
	result, err := engine.RunOnce(c)
	if err != nil {
		return Event{Addrs: addrs, Err: err}
	}
	log.Info("ddns result", "updated", result.Updated, "old", result.OldIP,
		"new", result.NewIP, "message", result.Message)
	if result.Timestamp.IsZero() {
		result.Timestamp = time.Now()
	}
	return Event{Addrs: addrs, Result: result}
}

// RunLoop loops until ctx is cancelled, reloading the config every cycle.
// onEvent, when non-nil, receives every completed cycle (success or failure).
func RunLoop(ctx context.Context, cfg config.Config, store ConfigStore, factory DepsFactory, interval time.Duration, onEvent func(Event)) {
	log.Info("daemon started", "interval", interval.String(), "config", store.Path())
	defer log.Info("daemon stopped")

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		ev := RunCycle(ctx, cfg, factory, interval)
		if onEvent != nil {
			onEvent(ev)
		}
		if ev.Err != nil && ctx.Err() == nil {
			log.Error("cycle failed", "error", ev.Err)
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
