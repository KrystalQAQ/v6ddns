// Package tray is the desktop shell around the service: a system tray icon
// with a small menu. All real UI lives in the local web console; the tray only
// opens it, triggers a manual update and shows the current state at a glance.
//
// Running the tray blocks the main goroutine, like any GUI event loop.
package tray

import (
	"context"
	_ "embed"
	"runtime"
	"time"

	"fyne.io/systray"

	"github.com/KrystalQAQ/v6ddns/internal/daemon"
	"github.com/KrystalQAQ/v6ddns/internal/service"
)

// Windows wants a real .ico (it carries the 16/24/32px variants the shell
// picks from). Everywhere else systray decodes the bytes with image.Decode —
// and only registers PNG — so an ICO embeds but silently fails to load.
//
//go:embed icon.ico
var icoIcon []byte

//go:embed icon.png
var pngIcon []byte

func platformIcon() []byte {
	if runtime.GOOS == "windows" {
		return icoIcon
	}
	return pngIcon
}

// Options wires the tray to the running service.
type Options struct {
	Service     *service.Service
	OpenConsole func()
	Cancel      func()
}

// Run blocks on the tray event loop until the user chooses 退出 or ctx is
// cancelled. onExit runs once the loop has stopped.
func Run(ctx context.Context, opts Options) {
	systray.Run(func() { onReady(ctx, opts) }, func() {})
}

func onReady(ctx context.Context, opts Options) {
	systray.SetIcon(platformIcon())
	systray.SetTooltip("v6ddns")
	if opts.OpenConsole != nil {
		systray.SetOnTapped(opts.OpenConsole)
	}

	openItem := systray.AddMenuItem("打开控制台", "在浏览器中打开 127.0.0.1 控制台")
	updateItem := systray.AddMenuItem("立即更新", "检测本机 IPv6 并同步 AAAA 记录")
	systray.AddSeparator()
	statusItem := systray.AddMenuItem("状态：启动中…", "")
	ipItem := systray.AddMenuItem("地址：—", "")
	domainItem := systray.AddMenuItem("域名：—", "")
	statusItem.Disable()
	ipItem.Disable()
	domainItem.Disable()
	systray.AddSeparator()
	quitItem := systray.AddMenuItem("退出", "退出 v6ddns")

	// Daemon cycles wake the refresher so the menu never lags far behind.
	wake := make(chan struct{}, 1)
	opts.Service.SetEventHandler(func(daemon.Event) {
		select {
		case wake <- struct{}{}:
		default:
		}
	})

	var last struct {
		status, ip, domain, tip string
	}
	refresh := func() {
		st := opts.Service.Status()
		state := "运行中"
		switch {
		case st.LastEvent.Running:
			state = "正在更新…"
		case st.LastEvent.Error != "":
			state = "上次运行失败"
		case !st.Listener.OK:
			state = "监听未启动"
		}
		setLabel(statusItem, &last.status, "状态："+state)
		ip := st.PublishedIP
		if ip == "" {
			ip = "等待首次检测"
		}
		setLabel(ipItem, &last.ip, "地址："+ip)
		domain := st.Domain
		if domain == "" {
			domain = "未配置"
		}
		setLabel(domainItem, &last.domain, "域名："+domain)
		if tip := "v6ddns · " + ip; tip != last.tip {
			last.tip = tip
			systray.SetTooltip(tip)
		}
	}

	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		refresh()
		for {
			select {
			case <-ctx.Done():
				systray.Quit()
				return
			case <-wake:
				refresh()
			case <-ticker.C:
				refresh()
			}
		}
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-openItem.ClickedCh:
				if opts.OpenConsole != nil {
					opts.OpenConsole()
				}
			case <-quitItem.ClickedCh:
				if opts.Cancel != nil {
					opts.Cancel()
				}
				systray.Quit()
				return
			}
		}
	}()

	go func() {
		for range updateItem.ClickedCh {
			updateItem.Disable()
			updateItem.SetTitle("正在更新…")
			c, cancel := context.WithTimeout(ctx, 2*time.Minute)
			_, _ = opts.Service.Update(c)
			cancel()
			updateItem.SetTitle("立即更新")
			updateItem.Enable()
			refresh()
		}
	}()
}

// setLabel only touches the menu when the text actually changed; Windows
// redraws the whole popup whenever an item is updated. MenuItem exposes no
// title getter, so the caller keeps the last value.
func setLabel(item *systray.MenuItem, last *string, text string) {
	if *last == text {
		return
	}
	*last = text
	item.SetTitle(text)
}
