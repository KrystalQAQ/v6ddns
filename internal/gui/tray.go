package gui

import (
	"fmt"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/driver/desktop"

	"github.com/KrystalQAQ/v6ddns/internal/daemon"
)

// setupTray installs the tray menu. The window is registered as the tray
// window so clicking the icon toggles it (where the platform supports it).
func (g *App) setupTray() {
	desk, ok := g.fyneApp.(desktop.App)
	if !ok {
		return
	}
	g.trayMenu = g.buildTrayMenu()
	desk.SetSystemTrayMenu(g.trayMenu)
	desk.SetSystemTrayIcon(trayIcon)
	desk.SetSystemTrayWindow(g.window)
}

func (g *App) buildTrayMenu() *fyne.Menu {
	status := fyne.NewMenuItem("状态：加载中…", nil)
	status.Disabled = true
	return fyne.NewMenu("v6ddns",
		fyne.NewMenuItem("显示窗口", func() { fyne.Do(func() { g.window.Show() }) }),
		fyne.NewMenuItem("立即更新", func() { g.manualUpdate(nil) }),
		fyne.NewMenuItemSeparator(),
		status,
		fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem("退出", func() {
			if g.opts.Cancel != nil {
				g.opts.Cancel()
			}
			g.fyneApp.Quit()
		}),
	)
}

func (g *App) refreshTrayMenu() {
	if g.trayMenu == nil {
		return
	}
	desk, ok := g.fyneApp.(desktop.App)
	if !ok {
		return
	}
	// Fyne menu labels are not live; rebuild the menu to refresh status text.
	g.trayMenu = g.buildTrayMenu()
	desk.SetSystemTrayMenu(g.trayMenu)
	desk.SetSystemTrayWindow(g.window)
}

// onDaemonEvent is called by the daemon loop after every cycle and by manual
// updates. It updates widgets and sends a notification when the result changes.
func (g *App) onDaemonEvent(ev daemon.Event) {
	g.mu.Lock()
	g.lastEvent = ev
	g.mu.Unlock()

	now := time.Now()
	g.notifyMutex.Lock()
	shouldNotify := now.Sub(g.lastNotify) > 30*time.Second
	if shouldNotify {
		g.lastNotify = now
	}
	g.notifyMutex.Unlock()

	fyne.Do(func() {
		if g.statusTime != nil {
			g.statusTime.SetText(now.Format("2006-01-02 15:04:05"))
		}
		if ev.Result.NewIP != "" {
			if g.statusIP != nil {
				g.statusIP.SetText(ev.Result.NewIP)
			}
			if g.ddnsLocalIP != nil {
				g.ddnsLocalIP.SetText(ev.Result.NewIP)
			}
		}
		if g.ddnsDomain != nil {
			g.ddnsDomain.SetText(g.currentConfig().Domain)
		}
		if ev.Err != nil {
			if g.statusMsg != nil {
				g.statusMsg.SetText("失败: " + ev.Err.Error())
			}
			setDot(g.statusDot, errorColor())
		} else if ev.Result.Updated {
			if g.statusMsg != nil {
				g.statusMsg.SetText(fmt.Sprintf("已更新 → %s", ev.Result.NewIP))
			}
			if g.cfIP != nil {
				g.cfIP.SetText(ev.Result.NewIP)
			}
			if g.cfState != nil {
				g.cfState.SetText("刚刚写入 Cloudflare")
			}
			setDot(g.statusDot, successColor())
		} else {
			if g.statusMsg != nil {
				g.statusMsg.SetText(ev.Result.Message)
			}
			setDot(g.statusDot, warningColor())
		}
		if g.ipTable != nil && len(ev.Addrs) > 0 {
			g.addrs = ev.Addrs
			g.ipTable.Refresh()
			g.updateIPSummary(ev.Addrs)
		}
		g.refreshTrayMenu()
	})

	if ev.Err != nil {
		if shouldNotify {
			g.fyneApp.SendNotification(fyne.NewNotification("v6ddns 更新失败", truncate(ev.Err.Error(), 120)))
		}
		return
	}
	if ev.Result.Updated && shouldNotify {
		g.fyneApp.SendNotification(fyne.NewNotification("v6ddns IPv6 已更新",
			fmt.Sprintf("%s → %s", valueOrDash(ev.Result.OldIP), ev.Result.NewIP)))
	}
}

func valueOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
