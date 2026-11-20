package gui

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

func (g *App) buildPages() []*container.TabItem {
	return []*container.TabItem{
		container.NewTabItem("总览", g.dashboardPage()),
		container.NewTabItem("配置", g.configPage()),
		container.NewTabItem("IPv6 检测", g.ipv6Page()),
		container.NewTabItem("DDNS", g.ddnsPage()),
		container.NewTabItem("入站检测", g.inboundPage()),
	}
}

// ---------- Dashboard ----------

func (g *App) dashboardPage() fyne.CanvasObject {
	g.statusIP = widget.NewLabel("—")
	g.statusIP.Wrapping = fyne.TextWrapWord
	g.statusTime = widget.NewLabel("从未")
	g.statusMsg = widget.NewLabel("等待首次更新…")
	g.statusMsg.Wrapping = fyne.TextWrapWord
	g.logView = widget.NewEntry()
	g.logView.MultiLine = true
	g.logView.Wrapping = fyne.TextWrapWord
	g.logView.Disable()

	refresh := widget.NewButton("刷新", func() { g.refreshDashboard() })
	update := widget.NewButton("立即更新", func() { g.manualUpdate(nil) })

	card := widget.NewCard("运行状态", "",
		container.NewGridWithColumns(2,
			widget.NewLabel("当前 IPv6"), g.statusIP,
			widget.NewLabel("上次更新"), g.statusTime,
			widget.NewLabel("结果"), g.statusMsg,
		))
	logCard := widget.NewCard("日志", "", g.logView)
	return container.NewBorder(
		container.NewHBox(refresh, update),
		nil, nil, nil,
		container.NewVSplit(card, logCard),
	)
}

func (g *App) refreshDashboard() {
	go func() {
		_, _, cf := g.deps()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		rec, err := cf.GetRecord(ctx, g.currentConfig().ZoneID, g.currentConfig().Domain)
		ip := "—"
		if err == nil {
			ip = rec.Content
		}
		fyne.Do(func() {
			g.statusIP.SetText(ip)
			g.refreshTrayMenu()
		})
	}()
	g.onDaemonEvent(daemon.Event{Addrs: g.addrs, Result: g.lastEvent.Result, Err: g.lastEvent.Err})
}

// ---------- Config ----------

func (g *App) configPage() fyne.CanvasObject {
	cfg := g.currentConfig()
	token := widget.NewPasswordEntry()
	token.SetText(cfg.APIToken)
	zone := widget.NewEntry()
	zone.SetText(cfg.ZoneID)
	domain := widget.NewEntry()
	domain.SetText(cfg.Domain)
	ttl := widget.NewEntry()
	ttl.SetText(strconv.Itoa(cfg.TTL))
	proxied := widget.NewCheck("橙云（proxied）", nil)
	proxied.SetChecked(cfg.Proxied)
	iface := widget.NewEntry()
	iface.SetText(cfg.InterfaceName)
	interval := widget.NewEntry()
	interval.SetText(cfg.Interval)
	policy := widget.NewSelect([]string{"stable-auto", "any-reachable", "manual"}, nil)
	policy.SetSelected(string(cfg.Policy))
	address := widget.NewEntry()
	address.SetText(cfg.Address)
	probes := widget.NewEntry()
	probes.SetText(strings.Join(cfg.ProbeTargets, ", "))
	probeTimeout := widget.NewEntry()
	probeTimeout.SetText(cfg.ProbeTimeout)
	worker := widget.NewEntry()
	worker.SetText(g.opts.WorkerURL)

	autostartCheck := widget.NewCheck("开机自启动（驻留托盘，默认关闭）", nil)
	if g.autoMgr != nil {
		if ok, err := g.autoMgr.IsEnabled(); err == nil {
			autostartCheck.SetChecked(ok)
		}
	} else {
		autostartCheck.Disable()
	}

	form := &widget.Form{
		Items: []*widget.FormItem{
			{Text: "API Token", Widget: token},
			{Text: "Zone ID", Widget: zone},
			{Text: "域名", Widget: domain},
			{Text: "TTL", Widget: ttl},
			{Text: "代理", Widget: proxied},
			{Text: "网卡", Widget: iface},
			{Text: "更新间隔", Widget: interval},
			{Text: "策略", Widget: policy},
			{Text: "手动 IPv6", Widget: address},
			{Text: "探测目标", Widget: probes},
			{Text: "探测超时", Widget: probeTimeout},
			{Text: "入站 Worker", Widget: worker},
			{Text: "自启动", Widget: autostartCheck},
		},
	}
	save := widget.NewButton("保存", func() {
		newCfg := config.Config{
			APIToken:      strings.TrimSpace(token.Text),
			ZoneID:        strings.TrimSpace(zone.Text),
			Domain:        strings.TrimSpace(domain.Text),
			Proxied:       proxied.Checked,
			InterfaceName: strings.TrimSpace(iface.Text),
			Interval:      strings.TrimSpace(interval.Text),
			Policy:        config.TargetPolicy(policy.Selected),
			Address:       strings.TrimSpace(address.Text),
			ProbeTargets:  splitTargets(probes.Text),
			ProbeTimeout:  strings.TrimSpace(probeTimeout.Text),
		}
		if v, err := strconv.Atoi(strings.TrimSpace(ttl.Text)); err == nil {
			newCfg.TTL = v
		}
		if newCfg.TTL == 0 {
			newCfg.TTL = 1
		}
		if newCfg.Interval == "" {
			newCfg.Interval = config.Default().Interval
		}
		if newCfg.ProbeTimeout == "" {
			newCfg.ProbeTimeout = config.Default().ProbeTimeout
		}
		if err := newCfg.Validate(); err != nil {
			dialog.ShowError(err, g.window)
			return
		}
		if err := g.opts.Store.Save(newCfg); err != nil {
			dialog.ShowError(err, g.window)
			return
		}
		g.mu.Lock()
		g.cfg = newCfg
		g.mu.Unlock()
		log.Default.SetSecrets()
		if newCfg.APIToken != "" {
			log.Default.AddSecret(newCfg.APIToken)
		}
		g.opts.WorkerURL = strings.TrimSpace(worker.Text)
		if d, err := time.ParseDuration(newCfg.Interval); err == nil {
			g.interval = d
		}
		if g.autoMgr != nil {
			exe, err := os.Executable()
			if err == nil {
				if autostartCheck.Checked {
					err = g.autoMgr.Enable(exe)
				} else {
					err = g.autoMgr.Disable()
				}
				if err != nil {
					dialog.ShowError(fmt.Errorf("自启动设置失败: %w", err), g.window)
				}
			}
		}
		dialog.ShowInformation("已保存", "配置已写入 "+g.opts.Store.Path(), g.window)
		g.refreshDashboard()
	})
	return container.NewBorder(nil, container.NewHBox(save), nil, nil, container.NewVScroll(form))
}

func splitTargets(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ---------- IPv6 ----------

func (g *App) ipv6Page() fyne.CanvasObject {
	g.ipTable = widget.NewTable(
		func() (int, int) { return len(g.addrs), 7 },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(i widget.TableCellID, o fyne.CanvasObject) {
			lbl := o.(*widget.Label)
			if i.Row >= len(g.addrs) {
				return
			}
			a := g.addrs[i.Row]
			vals := []string{
				a.IP.String(), a.Interface, string(a.Kind),
				strconv.FormatBool(a.Stable), strconv.FormatBool(a.Reachable),
				a.Method, a.Latency.String(),
			}
			if i.Col < len(vals) {
				lbl.SetText(vals[i.Col])
			}
		},
	)
	for c, width := range map[int]float32{0: 260, 1: 80, 2: 90, 3: 70, 4: 80, 5: 140, 6: 90} {
		g.ipTable.SetColumnWidth(c, width)
	}
	var detect *widget.Button
	detect = widget.NewButton("检测 IPv6", func() {
		detect.Disable()
		go func() {
			detector, _, _ := g.deps()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			addrs, err := detector.Detect(ctx)
			fyne.Do(func() {
				if err != nil {
					dialog.ShowError(err, g.window)
				} else {
					g.addrs = addrs
					g.ipTable.Refresh()
				}
				detect.Enable()
			})
		}()
	})
	head := container.NewHBox(widget.NewLabel("检测本机 IPv6 地址与出站可达性"), detect)
	return container.NewBorder(head, nil, nil, nil, g.ipTable)
}

// ---------- DDNS ----------

func (g *App) ddnsPage() fyne.CanvasObject {
	g.cfIP = widget.NewLabel("—")
	refresh := widget.NewButton("刷新记录", func() { g.refreshDashboard() })
	update := widget.NewButton("立即更新", func() { g.manualUpdate(nil) })
	card := widget.NewCard("Cloudflare AAAA 记录", "",
		container.NewGridWithColumns(2,
			widget.NewLabel("当前记录"), g.cfIP,
			widget.NewLabel("域名"), widget.NewLabel(g.currentConfig().Domain),
		))
	return container.NewBorder(container.NewHBox(refresh, update), nil, nil, nil, card)
}

// ---------- Inbound ----------

func (g *App) inboundPage() fyne.CanvasObject {
	g.inResult = widget.NewLabel("尚未检测")
	g.inResult.Wrapping = fyne.TextWrapWord
	portEntry := widget.NewEntry()
	portEntry.SetText("38080")
	var btn *widget.Button
	btn = widget.NewButton("开始检测", func() {
		port, err := strconv.Atoi(strings.TrimSpace(portEntry.Text))
		if err != nil || port < 1 || port > 65535 || port == 25 {
			dialog.ShowError(fmt.Errorf("端口必须是 1-65535 且不能是 25"), g.window)
			return
		}
		btn.Disable()
		g.inResult.SetText("正在从 Cloudflare 边缘检测…")
		go func() {
			_, _, cf := g.deps()
			prober := g.newProber(cf)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()
			// Prefer a reachable GUA from the last detection; fall back to the
			// configured manual address.
			target := g.currentConfig().Address
			for _, a := range g.addrs {
				if ipv6.IsPublicGUA(a.IP) && a.Reachable {
					target = a.IP.String()
					break
				}
			}
			if target == "" {
				fyne.Do(func() {
					g.inResult.SetText("没有可用 IPv6：先到「IPv6 检测」页检测，或在配置页填写手动地址")
					btn.Enable()
				})
				return
			}
			res, err := prober.Check(ctx, target, port)
			fyne.Do(func() {
				if err != nil {
					g.inResult.SetText("检测失败: " + err.Error())
				} else if res.Reachable {
					g.inResult.SetText(fmt.Sprintf("可达 ✅  延迟 %s\n目标 %s:%d（Cloudflare 边缘实测）", res.Latency, target, port))
				} else {
					g.inResult.SetText(fmt.Sprintf("不可达 ❌  目标 %s:%d\n%s", target, port, res.Err))
				}
				btn.Enable()
			})
		}()
	})
	card := widget.NewCard("从公网主动连入", "先把 target.254253.xyz 的 AAAA 指向待测地址，再由 Cloudflare Worker 从边缘 TCP 连接。",
		container.NewVBox(
			container.NewGridWithColumns(2, widget.NewLabel("端口"), portEntry),
			btn,
			g.inResult,
		))
	return container.NewCenter(card)
}

// manualUpdate runs one cycle outside the daemon loop. The atomic guard
// prevents overlapping clicks from the tray and the dashboard.
func (g *App) manualUpdate(after func(daemon.Event)) {
	if !g.manualRun.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer g.manualRun.Store(false)
		cfg := g.currentConfig()
		ev := daemon.RunCycle(context.Background(), cfg, g.opts.Factory, g.interval)
		g.onDaemonEvent(ev)
		if after != nil {
			after(ev)
		}
	}()
}
