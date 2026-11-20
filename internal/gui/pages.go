package gui

import (
	"context"
	"fmt"
	"image/color"
	"os"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
	"github.com/KrystalQAQ/v6ddns/internal/log"
)

var ipHeaders = []string{"地址", "网卡", "类型", "稳定", "可达", "延迟"}

// pageHeader renders a page title, a short subtitle and optional right-side
// actions.
func pageHeader(title, subtitle string, actions ...fyne.CanvasObject) fyne.CanvasObject {
	heading := canvas.NewText(title, uiColor(theme.ColorNameForeground))
	heading.TextSize = 24
	heading.TextStyle = fyne.TextStyle{Bold: true}
	left := container.NewVBox(heading, mutedText(subtitle))
	if len(actions) == 0 {
		return left
	}
	return container.NewBorder(nil, nil, nil, container.NewHBox(actions...), left)
}

// ---------- Dashboard ----------

func (g *App) dashboardPage() fyne.CanvasObject {
	g.statusIP = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true, Bold: true})
	g.statusIP.Wrapping = fyne.TextWrapWord
	g.statusTime = widget.NewLabel("从未")
	g.statusMsg = widget.NewLabel("等待首次更新…")
	g.statusMsg.Wrapping = fyne.TextWrapWord
	g.statusDot = statusDot(uiColor(theme.ColorNamePlaceHolder))

	g.logView = widget.NewMultiLineEntry()
	g.logView.Wrapping = fyne.TextWrapWord
	g.logView.Disable()

	ipCard := panel("当前发布地址", "最近一次写入 Cloudflare 的 IPv6",
		container.NewVBox(g.statusIP, container.NewHBox(dotBox(g.statusDot), g.statusMsg)))
	timeCard := panel("上次更新", "按配置间隔自动运行",
		container.NewVBox(
			widget.NewLabelWithStyle("时间", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
			g.statusTime,
		))
	actionCard := panel("操作", "", container.NewHBox(
		widget.NewButtonWithIcon("立即更新", theme.MediaPlayIcon(), func() { g.manualUpdate(nil) }),
		widget.NewButtonWithIcon("刷新记录", theme.ViewRefreshIcon(), g.refreshDashboard),
	))
	logCard := panel("日志", "最近 200 行", g.logView)

	body := container.NewVSplit(container.NewVBox(
		container.NewGridWithColumns(2, ipCard, timeCard),
		actionCard,
	), logCard)
	body.SetOffset(0.42)
	return container.NewBorder(pageHeader("总览", "本机 IPv6 的发布状态与运行日志"), nil, nil, nil, body)
}

func (g *App) refreshDashboard() {
	cfg := g.currentConfig()
	go func() {
		_, _, cf := g.deps()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if strings.TrimSpace(cfg.ZoneID) == "" || strings.TrimSpace(cfg.Domain) == "" {
			fyne.Do(func() {
				if g.cfIP != nil {
					g.cfIP.SetText("—")
				}
				if g.cfState != nil {
					g.cfState.SetText("未配置 Zone ID / 域名")
				}
			})
			return
		}
		rec, err := cf.GetRecord(ctx, cfg.ZoneID, cfg.Domain)
		fyne.Do(func() {
			if g.ddnsDomain != nil {
				g.ddnsDomain.SetText(cfg.Domain)
			}
			last := g.lastEventCopy()
			if g.ddnsLocalIP != nil {
				g.ddnsLocalIP.SetText(valueOrDash(last.Result.NewIP))
			}
			if err != nil {
				if g.cfIP != nil {
					g.cfIP.SetText("—")
				}
				if g.cfState != nil {
					g.cfState.SetText("读取失败：" + err.Error())
				}
				return
			}
			if g.cfIP != nil {
				g.cfIP.SetText(rec.Content)
			}
			if g.cfState != nil {
				if last.Result.NewIP != "" && rec.Content == last.Result.NewIP {
					g.cfState.SetText("与最近一次发布地址一致")
				} else {
					g.cfState.SetText("线上记录（等待下一轮同步）")
				}
			}
		})
	}()
}

func (g *App) lastEventCopy() daemon.Event {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.lastEvent
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
	proxied := widget.NewCheck("橙云代理（入站检测必须关闭）", nil)
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
	listenPort := widget.NewEntry()
	listenPort.SetText(strconv.Itoa(cfg.ListenPort))
	worker := widget.NewEntry()
	worker.SetText(g.workerURL(cfg))

	requireInbound := widget.NewCheck("仅在入站可达时写入 AAAA", nil)
	requireInbound.SetChecked(cfg.RequireInbound)
	inboundPort := widget.NewEntry()
	inboundPort.SetPlaceHolder("留空则使用监听端口")
	if cfg.InboundPort > 0 {
		inboundPort.SetText(strconv.Itoa(cfg.InboundPort))
	}
	probeBase := widget.NewEntry()
	probeBase.SetText(cfg.ProbeBase)
	if cfg.Domain != "" {
		probeBase.SetPlaceHolder(cfg.Domain + "（留空即使用域名）")
	}

	autostartCheck := widget.NewCheck("开机自启动（驻留托盘）", nil)
	if g.autoMgr != nil {
		if ok, err := g.autoMgr.IsEnabled(); err == nil {
			autostartCheck.SetChecked(ok)
		}
	} else {
		autostartCheck.Disable()
	}

	cfForm := &widget.Form{Items: []*widget.FormItem{
		{Text: "API Token *", Widget: token},
		{Text: "Zone ID *", Widget: zone},
		{Text: "域名 *", Widget: domain},
		{Text: "TTL", Widget: ttl},
		{Text: "代理", Widget: proxied},
	}}
	srcForm := &widget.Form{Items: []*widget.FormItem{
		{Text: "网卡", Widget: iface},
		{Text: "策略", Widget: policy},
		{Text: "手动 IPv6", Widget: address},
		{Text: "探测目标", Widget: probes},
		{Text: "探测超时", Widget: probeTimeout},
	}}
	runForm := &widget.Form{Items: []*widget.FormItem{
		{Text: "更新间隔", Widget: interval},
		{Text: "监听端口", Widget: listenPort},
		{Text: "入站 Worker", Widget: worker},
		{Text: "自启动", Widget: autostartCheck},
	}}
	gateForm := &widget.Form{Items: []*widget.FormItem{
		{Text: "可达才绑定", Widget: requireInbound},
		{Text: "验证端口", Widget: inboundPort},
		{Text: "验证基域", Widget: probeBase},
	}}

	cards := container.NewVBox(
		panel("Cloudflare 账户", "带 * 必填；域名同时用于 DDNS 与入站检测", cfForm),
		panel("IPv6 来源", "决定发布哪个本机地址", srcForm),
		panel("运行", "启动后自动监听端口并常驻托盘", runForm),
		panel("入站闸门", "候选地址先写到 v6-<地址> 子域，边缘实测通过后才更新主域名", gateForm),
	)

	save := widget.NewButtonWithIcon("保存配置", theme.DocumentSaveIcon(), func() {
		newCfg := config.Config{
			APIToken:       strings.TrimSpace(token.Text),
			ZoneID:         strings.TrimSpace(zone.Text),
			Domain:         strings.TrimSpace(domain.Text),
			Proxied:        proxied.Checked,
			InterfaceName:  strings.TrimSpace(iface.Text),
			Interval:       strings.TrimSpace(interval.Text),
			Policy:         config.TargetPolicy(policy.Selected),
			Address:        strings.TrimSpace(address.Text),
			ProbeTargets:   splitTargets(probes.Text),
			ProbeTimeout:   strings.TrimSpace(probeTimeout.Text),
			InboundWorker:  strings.TrimSpace(worker.Text),
			RequireInbound: requireInbound.Checked,
			ProbeBase:      strings.TrimSpace(probeBase.Text),
		}
		newCfg.TTL = 1
		if raw := strings.TrimSpace(ttl.Text); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				dialog.ShowError(fmt.Errorf("TTL 必须是整数"), g.window)
				return
			}
			newCfg.TTL = v
		}
		newCfg.ListenPort = config.Default().ListenPort
		if raw := strings.TrimSpace(listenPort.Text); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				dialog.ShowError(fmt.Errorf("监听端口必须是整数"), g.window)
				return
			}
			newCfg.ListenPort = v
		}
		newCfg.InboundPort = 0
		if raw := strings.TrimSpace(inboundPort.Text); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				dialog.ShowError(fmt.Errorf("验证端口必须是整数"), g.window)
				return
			}
			newCfg.InboundPort = v
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
		if g.ddnsDomain != nil {
			g.ddnsDomain.SetText(newCfg.Domain)
		}
		g.startListener(newCfg.ListenPort)
		dialog.ShowInformation("已保存", "配置已写入 "+g.opts.Store.Path(), g.window)
		g.refreshDashboard()
	})
	save.Importance = widget.HighImportance

	return container.NewBorder(pageHeader("配置", "所有修改保存后立即生效", save), nil, nil, nil,
		container.NewVScroll(cards))
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
		func() (int, int) { return len(g.addrs) + 1, len(ipHeaders) },
		func() fyne.CanvasObject { return widget.NewLabel("") },
		func(id widget.TableCellID, o fyne.CanvasObject) {
			lbl := o.(*widget.Label)
			if id.Row == 0 {
				lbl.TextStyle = fyne.TextStyle{Bold: true}
				if id.Col < len(ipHeaders) {
					lbl.SetText(ipHeaders[id.Col])
				}
				lbl.Refresh()
				return
			}
			lbl.TextStyle = fyne.TextStyle{}
			idx := id.Row - 1
			if idx < 0 || idx >= len(g.addrs) {
				lbl.SetText("")
				lbl.Refresh()
				return
			}
			a := g.addrs[idx]
			vals := []string{
				a.IP.String(), a.Interface, string(a.Kind),
				boolCN(a.Stable), boolCN(a.Reachable),
				a.Latency.String(),
			}
			if id.Col < len(vals) {
				lbl.SetText(vals[id.Col])
			}
			lbl.Refresh()
		},
	)
	for c, width := range map[int]float32{0: 250, 1: 200, 2: 70, 3: 50, 4: 50, 5: 70} {
		g.ipTable.SetColumnWidth(c, width)
	}

	g.ipCount = widget.NewLabel("尚未检测")
	detect := widget.NewButtonWithIcon("检测 IPv6", theme.SearchIcon(), nil)
	detect.Importance = widget.HighImportance
	detect.OnTapped = func() {
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
					g.updateIPSummary(addrs)
				}
				detect.Enable()
			})
		}()
	}

	head := container.NewVBox(pageHeader("IPv6 地址", "枚举本机地址并做源地址绑定可达性探测", detect), g.ipCount)
	return container.NewBorder(head, nil, nil, nil, g.ipTable)
}

func (g *App) updateIPSummary(addrs []ipv6.Address) {
	if g.ipCount == nil {
		return
	}
	gua, reachable := 0, 0
	for _, a := range addrs {
		if a.Kind == ipv6.KindGUA {
			gua++
			if a.Reachable {
				reachable++
			}
		}
	}
	g.ipCount.SetText(fmt.Sprintf("%d 个地址 · %d 个公网 GUA · %d 个可达", len(addrs), gua, reachable))
}

func boolCN(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

// ---------- DDNS ----------

func (g *App) ddnsPage() fyne.CanvasObject {
	g.cfIP = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true, Bold: true})
	g.cfIP.Wrapping = fyne.TextWrapWord
	g.cfState = widget.NewLabel("—")
	g.ddnsDomain = widget.NewLabel("—")
	g.ddnsLocalIP = widget.NewLabelWithStyle("—", fyne.TextAlignLeading, fyne.TextStyle{Monospace: true})

	recordCard := panel("Cloudflare AAAA", "当前线上记录", widget.NewForm(
		widget.NewFormItem("域名", g.ddnsDomain),
		widget.NewFormItem("记录", g.cfIP),
		widget.NewFormItem("状态", g.cfState),
	))
	localCard := panel("本机", "最近一次发布的地址", widget.NewForm(
		widget.NewFormItem("IPv6", g.ddnsLocalIP),
		widget.NewFormItem("说明", mutedText("直连必须灰云（DNS only）")),
	))
	actions := container.NewHBox(
		widget.NewButtonWithIcon("刷新记录", theme.ViewRefreshIcon(), g.refreshDashboard),
		widget.NewButtonWithIcon("立即更新", theme.MediaPlayIcon(), func() { g.manualUpdate(nil) }),
	)
	return container.NewBorder(pageHeader("DDNS", "查看并立即同步 Cloudflare 的 AAAA 记录", actions), nil, nil, nil,
		container.NewVBox(recordCard, localCard))
}

// ---------- Inbound ----------

func (g *App) inboundPage() fyne.CanvasObject {
	g.inListen = widget.NewLabel("启动中…")
	g.inListenDot = statusDot(uiColor(theme.ColorNamePlaceHolder))
	g.inDomain = widget.NewLabel("—")
	g.inPort = widget.NewLabel("—")
	g.inResult = widget.NewLabel("尚未检测")
	g.inResult.Wrapping = fyne.TextWrapWord
	g.inResultDot = statusDot(uiColor(theme.ColorNamePlaceHolder))

	var check *widget.Button
	check = widget.NewButtonWithIcon("从公网检测入站", theme.DownloadIcon(), func() {
		g.runInboundCheck(check)
	})
	check.Importance = widget.HighImportance

	listenCard := panel("本机监听", "启动即监听；检测直接复用这个端口", widget.NewForm(
		widget.NewFormItem("状态", container.NewHBox(dotBox(g.inListenDot), g.inListen)),
		widget.NewFormItem("域名", g.inDomain),
		widget.NewFormItem("端口", g.inPort),
	))
	checkCard := panel("从公网主动连入", "先绑定域名，再由 Cloudflare 边缘发起连接",
		container.NewVBox(
			container.NewHBox(check),
			container.NewBorder(nil, nil, dotBox(g.inResultDot), nil, g.inResult),
		))

	return container.NewBorder(pageHeader("入站检测", "验证公网能否通过 IPv6 直接连到本机"), nil, nil, nil,
		container.NewVBox(listenCard, checkCard))
}

func (g *App) runInboundCheck(btn *widget.Button) {
	cfg := g.currentConfig()
	if strings.TrimSpace(cfg.Domain) == "" {
		dialog.ShowError(fmt.Errorf("请先在「配置」页填写域名"), g.window)
		return
	}
	if cfg.Proxied {
		dialog.ShowError(fmt.Errorf("域名开着橙云代理，Worker 会连到 Cloudflare 而不是本机；请改成灰云"), g.window)
		return
	}
	port := cfg.EffectiveInboundPort()
	if port == cfg.ListenPort {
		if _, err := g.listenerState(); err != nil {
			dialog.ShowError(fmt.Errorf("本机监听没有启动：%w", err), g.window)
			return
		}
	}
	worker := g.workerURL(cfg)
	btn.Disable()
	if cfg.RequireInbound {
		g.setInboundResult("正在从公网验证候选 IPv6，通过后写入 "+cfg.Domain+" …", primaryColor())
	} else {
		g.setInboundResult("正在把本机 IPv6 写入 "+cfg.Domain+" …", primaryColor())
	}

	go func() {
		defer fyne.Do(btn.Enable)
		ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()

		_, engine, _ := g.deps()
		res, err := engine.RunOnce(ctx)
		if err != nil {
			fyne.Do(func() { g.setInboundResult("入站验证/绑定失败："+err.Error(), errorColor()) })
			return
		}
		if res.NewIP == "" {
			fyne.Do(func() { g.setInboundResult("没有可用的公网 IPv6："+res.Message, warningColor()) })
			return
		}

		fyne.Do(func() {
			if g.statusIP != nil {
				g.statusIP.SetText(res.NewIP)
			}
			if g.ddnsLocalIP != nil {
				g.ddnsLocalIP.SetText(res.NewIP)
			}
			g.setInboundResult(fmt.Sprintf("已绑定 %s → %s\n正在从 Cloudflare 边缘连接 %s:%d …",
				cfg.Domain, res.NewIP, cfg.Domain, port), primaryColor())
		})

		prober := inbound.NewProber(worker, nil, cfg.Domain)
		out, err := prober.Check(ctx, port)
		fyne.Do(func() {
			if err != nil {
				g.setInboundResult("检测失败："+err.Error(), errorColor())
				return
			}
			if out.Reachable {
				g.setInboundResult(fmt.Sprintf("可达 ✅  %s\n%s:%d → %s（Cloudflare 边缘实测）",
					out.Latency, cfg.Domain, port, res.NewIP), successColor())
			} else {
				g.setInboundResult(fmt.Sprintf("不可达 ❌  %s:%d\n%s",
					cfg.Domain, port, out.Err), errorColor())
			}
		})
	}()
}

func (g *App) setInboundResult(text string, col color.Color) {
	if g.inResult != nil {
		g.inResult.SetText(text)
	}
	setDot(g.inResultDot, col)
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
