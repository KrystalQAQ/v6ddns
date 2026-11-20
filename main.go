// Command v6ddns is a Cloudflare IPv6 DDNS tool with a tray icon and a local
// web console.
//
// Usage:
//
//	v6ddns                 # start, open the console at 127.0.0.1:38081
//	v6ddns --tray          # start hidden (used by autostart); no browser
//	v6ddns --daemon        # run continuously with no UI (cron/systemd)
//	v6ddns --once          # detect and update once, then exit
//	v6ddns --config PATH   # use a specific config file
//	v6ddns --icmp          # additionally try privileged ICMPv6 probes
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/KrystalQAQ/v6ddns/internal/autostart"
	"github.com/KrystalQAQ/v6ddns/internal/browser"
	"github.com/KrystalQAQ/v6ddns/internal/cloudflare"
	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/console"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
	"github.com/KrystalQAQ/v6ddns/internal/service"
	"github.com/KrystalQAQ/v6ddns/internal/tray"
	"github.com/KrystalQAQ/v6ddns/internal/wol"
)

// version is overridden at build time with -X main.version=...
var version = ""

func main() {
	var (
		daemonMode    = flag.Bool("daemon", false, "run in the background without a UI")
		consoleMode   = flag.Bool("console", false, "with --daemon, also serve the web console")
		once          = flag.Bool("once", false, "detect and update once, then exit")
		trayMode      = flag.Bool("tray", false, "start in the tray without opening the console")
		configPath    = flag.String("config", "", "path to the configuration file")
		icmp          = flag.Bool("icmp", false, "also try ICMPv6 probes (needs raw-socket privileges)")
		inboundWorker = flag.String("inbound-worker", inbound.DefaultWorkerURL, "inbound probe Worker URL")
		neighbors     = flag.Bool("neigh", false, "list IPv6 neighbours (LAN devices) and exit")
		wake          = flag.String("wake", "", "broadcast a Wake-on-LAN packet to this MAC and exit")
	)
	flag.Parse()

	if *daemonMode && *once {
		fmt.Fprintln(os.Stderr, "--daemon and --once are mutually exclusive")
		os.Exit(2)
	}
	if *wake != "" {
		if err := printWake(*wake); err != nil {
			fmt.Fprintln(os.Stderr, "wake:", err)
			os.Exit(1)
		}
		return
	}
	if *neighbors {
		if err := printNeighbors(); err != nil {
			fmt.Fprintln(os.Stderr, "neigh:", err)
			os.Exit(1)
		}
		return
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
	// and whenever the console's config page is saved.
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
		if *consoleMode {
			if err := runDaemonWithConsole(ctx, cfg, store, factory, *inboundWorker); err != nil {
				fmt.Fprintln(os.Stderr, "v6ddns:", err)
				os.Exit(1)
			}
			return
		}
		if srv := startGateListener(cfg); srv != nil {
			defer srv.Close()
		}
		daemon.RunLoop(ctx, cfg, store, factory, interval, nil)
	default:
		if err := runDesktop(ctx, stop, cfg, store, factory, *inboundWorker, *trayMode); err != nil {
			fmt.Fprintln(os.Stderr, "v6ddns:", err)
			os.Exit(1)
		}
	}
}

// printNeighbors is the --neigh diagnostic: a passive view of the kernel's
// IPv6 neighbour table. Devices appear only after they have sent IPv6 traffic.
func printWake(mac string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := wol.Wake(ctx, mac, wol.Options{})
	if err != nil {
		return err
	}
	fmt.Printf("magic packet for %s sent to:\n", res.MAC)
	for _, target := range res.Targets {
		fmt.Printf("  %s\n", target)
	}
	for _, problem := range res.Errors {
		fmt.Printf("  failed: %s\n", problem)
	}
	fmt.Println("\nThe network card and firmware must both accept wake-on-LAN, and the")
	fmt.Println("link must stay powered while the machine sleeps.")
	return nil
}

func printNeighbors() error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	list, err := ipv6.SystemNeighborProvider{}.Neighbors(ctx)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Println("no IPv6 neighbours")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MAC\tADDRESS\tIFACE\tSTATE\tTYPE")
	for _, n := range list {
		typ := string(n.Kind)
		if n.GUA {
			typ = "GUA"
		}
		if n.EUI64 {
			typ += " EUI-64"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", n.MAC, n.IP, n.Interface, n.State, typ)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Println("\nPassive view only: a device appears after it sends IPv6 traffic.")
	return nil
}

// consoleOptions reads the deployment secrets from the environment. The
// password never lives in config.yaml, so saving the console form cannot leak
// it and a config backup does not contain it.
func consoleOptions(cfg config.Config) console.Options {
	user := strings.TrimSpace(os.Getenv("V6DDNS_ADMIN_USER"))
	if user == "" {
		user = "admin"
	}
	return console.Options{
		Username:     user,
		Password:     os.Getenv("V6DDNS_ADMIN_PASSWORD"),
		TLSCert:      os.Getenv("V6DDNS_ADMIN_TLS_CERT"),
		TLSKey:       os.Getenv("V6DDNS_ADMIN_TLS_KEY"),
		AllowedHosts: cfg.AdminHostsList(),
	}
}

// validateConsoleExposure refuses the dangerous combination of a public bind
// without authentication. The console can read the Cloudflare token.
func validateConsoleExposure(cfg config.Config) error {
	if !cfg.HasWildcardBind() {
		return nil
	}
	if strings.TrimSpace(os.Getenv("V6DDNS_ADMIN_PASSWORD")) == "" {
		return fmt.Errorf("admin_bind contains a wildcard address; set V6DDNS_ADMIN_PASSWORD")
	}
	if len(cfg.AdminHostsList()) == 0 {
		return fmt.Errorf("admin_bind contains a wildcard address; set admin_hosts to the public hostname")
	}
	return nil
}

// runDesktop starts the service, the loopback console and the tray. It returns
// when the tray is closed or the process receives a signal.
func runDesktop(
	ctx context.Context,
	cancel func(),
	cfg config.Config,
	store *config.FileStore,
	factory daemon.DepsFactory,
	workerURL string,
	startHidden bool,
) error {
	buf := log.NewBuffer(500)
	logger := log.New(io.MultiWriter(os.Stderr, buf), log.LevelInfo)
	if cfg.APIToken != "" {
		logger.AddSecret(cfg.APIToken)
	}
	logger.AddSecret(os.Getenv("V6DDNS_ADMIN_PASSWORD"))
	log.Default = logger

	if err := validateConsoleExposure(cfg); err != nil {
		return err
	}
	if cfg.HasWildcardBind() && os.Getenv("V6DDNS_ADMIN_TLS_CERT") == "" {
		logger.Warn("console is publicly bound without TLS; use a TLS reverse proxy/tunnel or V6DDNS_ADMIN_TLS_CERT/KEY")
	}

	svc, err := service.New(service.Options{
		Config:    cfg,
		Store:     store,
		Factory:   factory,
		WorkerURL: workerURL,
		AutoMgr:   autostart.New(),
		Buffer:    buf,
		Logger:    logger,
		Version:   buildVersion(),
	})
	if err != nil {
		return err
	}

	consoleOpts := consoleOptions(cfg)
	consoleSrv, err := console.StartWithOptions(svc, adminListenAddrs(cfg, cfg.AdminPort), consoleOpts)
	if err != nil {
		logger.Warn("console port unavailable; using an ephemeral port",
			"binds", cfg.AdminBind, "error", err)
		consoleSrv, err = console.StartWithOptions(svc, adminListenAddrs(cfg, 0), consoleOpts)
		if err != nil {
			return fmt.Errorf("start console: %w", err)
		}
	}
	defer consoleSrv.Close()

	svc.Start(ctx)
	defer svc.Close()

	logger.Info("console ready", "url", consoleSrv.URL())
	fmt.Fprintln(os.Stderr, "控制台:", consoleSrv.URL())

	openConsole := func() {
		if err := browser.Open(consoleSrv.URL()); err != nil {
			logger.Warn("open browser failed", "url", consoleSrv.URL(), "error", err)
		}
	}
	if !startHidden {
		openConsole()
	}

	tray.Run(ctx, tray.Options{
		Service:     svc,
		OpenConsole: openConsole,
		Cancel:      cancel,
	})
	return nil
}

// runDaemonWithConsole is the headless server mode: the same service loop as
// the desktop build, but without a tray or browser, plus the web console bound
// to admin_bind/admin_port (loopback unless explicitly configured otherwise).
func runDaemonWithConsole(
	ctx context.Context,
	cfg config.Config,
	store *config.FileStore,
	factory daemon.DepsFactory,
	workerURL string,
) error {
	buf := log.NewBuffer(500)
	logger := log.New(io.MultiWriter(os.Stdout, buf), log.LevelInfo)
	if cfg.APIToken != "" {
		logger.AddSecret(cfg.APIToken)
	}
	logger.AddSecret(os.Getenv("V6DDNS_ADMIN_PASSWORD"))
	log.Default = logger

	if err := validateConsoleExposure(cfg); err != nil {
		return err
	}
	if cfg.HasWildcardBind() && os.Getenv("V6DDNS_ADMIN_TLS_CERT") == "" {
		logger.Warn("console is publicly bound without TLS; use a TLS reverse proxy/tunnel or V6DDNS_ADMIN_TLS_CERT/KEY")
	}

	svc, err := service.New(service.Options{
		Config:    cfg,
		Store:     store,
		Factory:   factory,
		WorkerURL: workerURL,
		// No OS autostart manager here: headless installs are supervised by
		// systemd/procd, and XDG autostart makes no sense on a server.
		Buffer:  buf,
		Logger:  logger,
		Version: buildVersion(),
	})
	if err != nil {
		return err
	}

	consoleSrv, err := console.StartWithOptions(svc, adminListenAddrs(cfg, cfg.AdminPort), consoleOptions(cfg))
	if err != nil {
		return fmt.Errorf("start console on %s: %w", cfg.AdminBind, err)
	}
	defer consoleSrv.Close()

	svc.Start(ctx)
	defer svc.Close()

	logger.Info("console ready", "url", consoleSrv.URL(), "binds", cfg.AdminBind,
		"auth", consoleSrv.AuthEnabled(), "tls", consoleSrv.TLSEnabled())
	fmt.Fprintln(os.Stderr, "控制台:", consoleSrv.URL())
	<-ctx.Done()
	return nil
}

// adminListenAddrs expands the comma-separated admin_bind list into
// host:port addresses for the console.
func adminListenAddrs(cfg config.Config, port int) []string {
	binds := cfg.AdminBinds()
	addrs := make([]string, 0, len(binds))
	for _, bind := range binds {
		addrs = append(addrs, net.JoinHostPort(bind, strconv.Itoa(port)))
	}
	return addrs
}

func buildVersion() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
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
