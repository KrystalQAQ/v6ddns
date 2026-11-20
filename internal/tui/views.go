package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/KrystalQAQ/v6ddns/internal/config"
	"github.com/KrystalQAQ/v6ddns/internal/ddns"
	"github.com/KrystalQAQ/v6ddns/internal/inbound"
	"github.com/KrystalQAQ/v6ddns/internal/ipv6"
)

var (
	accentStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("75")).Bold(true)
	dimStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	greenStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	yellowStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	redStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("203"))
	badgeStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("232")).Background(lipgloss.Color("75")).Padding(0, 1)
	focusStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("230")).Background(lipgloss.Color("238")).Padding(0, 1)
)

func (m *Model) headerView() string {
	tabs := make([]string, len(tabNames))
	for i, name := range tabNames {
		if tab(i) == m.active {
			tabs[i] = badgeStyle.Render(fmt.Sprintf(" %d %s ", i+1, name))
		} else {
			tabs[i] = dimStyle.Render(fmt.Sprintf(" %d %s ", i+1, name))
		}
	}
	return accentStyle.Render("v6ddns") + "  " + strings.Join(tabs, " ") +
		"  " + dimStyle.Render(config.MaskToken(m.cfg.Domain+" ("+m.cfg.ZoneID+")", m.cfg.APIToken))
}

func (m *Model) helpView() string {
	keys := []string{"Tab/1-5 切页", "i 入站检测", "r 刷新", "q/Ctrl+C 退出"}
	switch m.active {
	case tabConfig:
		keys = []string{"Tab/↑↓ 移动", "Space 切换选项", "Enter/Ctrl+S 保存", "Esc 放弃返回"}
	case tabIPv6:
		keys = []string{"c 检测", "i 入站检测", "r 重测", "Tab 切页", "q 退出"}
	case tabDDNS:
		keys = []string{"u 立即更新", "i 入站检测", "r 刷新", "Tab 切页", "q 退出"}
	case tabInbound:
		keys = []string{"i 开始/重测", "Tab 编辑端口", "r 刷新", "Tab 切页", "q 退出"}
	default:
		keys = append([]string{"c 检测", "u 更新"}, keys...)
	}
	hint := strings.Join(keys, "  •  ")
	if m.message != "" {
		line := m.message
		style := greenStyle
		if m.messageIsErr {
			style = redStyle
		}
		hint = style.Render(line) + "\n" + dimStyle.Render(hint)
	}
	return dimStyle.Render("────────────────────────────────────────") + "\n" + hint
}

func (m *Model) statusLine(label, value string) string {
	return fmt.Sprintf("  %-16s %s\n", label, value)
}

func (m *Model) dashboardView(height int) string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("总览") + "\n\n")
	b.WriteString(dimStyle.Render("配置") + "\n")
	b.WriteString(m.statusLine("域名", m.cfg.Domain))
	b.WriteString(m.statusLine("Zone ID", m.cfg.ZoneID))
	tokenDisplay := "（未设置）"
	if m.cfg.APIToken != "" {
		tokenDisplay = strings.Repeat("•", 8) + " (已设置)"
	}
	b.WriteString("  " + fmt.Sprintf("%-16s %s", "API Token", tokenDisplay) + "\n")
	b.WriteString(m.statusLine("策略", string(m.cfg.Policy)))
	b.WriteString(m.statusLine("TTL / Proxied", fmt.Sprintf("%d / %t", m.cfg.TTL, m.cfg.Proxied)))
	b.WriteString(m.statusLine("网卡 / 间隔", m.cfg.InterfaceName+" (全部) / "+m.cfg.Interval))
	b.WriteString("\n" + dimStyle.Render("最近检测") + "\n")
	if m.lastDetectErr != "" {
		b.WriteString(redStyle.Render("  检测失败: "+m.lastDetectErr) + "\n")
	} else if m.lastDetectAt.IsZero() {
		b.WriteString(dimStyle.Render("  尚未检测，按 c 开始") + "\n")
	} else {
		count := 0
		for _, a := range m.lastDetect {
			if a.Kind == ipv6.KindGUA && a.Reachable {
				count++
			}
		}
		b.WriteString(m.statusLine("时间", m.lastDetectAt.Format("15:04:05")))
		b.WriteString(m.statusLine("地址数", fmt.Sprintf("%d (可达 GUA: %d)", len(m.lastDetect), count)))
		if ip, src := m.candidate(); ip != "" {
			b.WriteString(m.statusLine("候选 IP", ip+" ("+src+")"))
		} else {
			b.WriteString(m.statusLine("候选 IP", redStyle.Render("无可用地址")))
		}
	}
	b.WriteString("\n" + dimStyle.Render("最近 DDNS") + "\n")
	if m.lastResultErr != "" {
		b.WriteString(redStyle.Render("  更新失败: ") + m.lastResultErr + "\n")
	} else if m.lastResult.Timestamp.IsZero() {
		b.WriteString(dimStyle.Render("  尚未更新，按 u 立即更新") + "\n")
	} else {
		b.WriteString(m.statusLine("时间", m.lastResult.Timestamp.Format("15:04:05")))
		b.WriteString("  " + fmt.Sprintf("%-16s ", "结果") + colorizeResult(m.lastResult) + "\n")
	}
	b.WriteString("\n" + dimStyle.Render("日志 (最近 "+fmt.Sprint(len(m.logLines))+" 条)") + "\n")
	logs := m.logLines
	if len(logs) > height {
		logs = logs[len(logs)-height:]
	}
	for _, line := range logs {
		b.WriteString("  " + colorizeLog(line) + "\n")
	}
	return b.String()
}

func colorizeLog(line string) string {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "error") || strings.Contains(lower, "fatal"):
		return redStyle.Render(line)
	case strings.Contains(lower, "warn"):
		return yellowStyle.Render(line)
	default:
		return dimStyle.Render(line)
	}
}

func (m *Model) configView() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("配置 (修改后 Ctrl+S / Enter 保存到 "+m.storePath()+")") + "\n\n")
	labels := []string{
		"API Token", "Zone ID", "域名", "TTL", "Proxied (灰云=false)",
		"网卡 (空=全部)", "更新间隔", "目标策略", "手动 IPv6",
	}
	for i, label := range labels {
		f := field(i)
		marker := "  "
		if f == m.focus {
			marker = "> "
		}
		switch f {
		case fieldProxied:
			value := "false (灰云/直连)"
			if m.proxied {
				value = "true (橙云代理)"
			}
			b.WriteString(fmt.Sprintf("%s%-20s %s\n", marker, label, m.fieldStyle(f, value)))
		case fieldPolicy:
			b.WriteString(fmt.Sprintf("%s%-20s %s\n", marker, label, m.fieldStyle(f, string(m.policy)+"  (Space/←/→ 切换)")))
		case fieldSave:
			continue
		default:
			idx, ok := m.inputFor(f)
			if !ok {
				continue
			}
			b.WriteString(fmt.Sprintf("%s%-20s %s\n", marker, label, m.fieldStyle(f, m.inputs[idx].View())))
		}
	}
	saveMarker := "  "
	if m.focus == fieldSave {
		saveMarker = "> "
	}
	b.WriteString("\n" + saveMarker + m.fieldStyle(fieldSave, "[ 保存配置 ]") + "\n")
	return b.String()
}

func (m *Model) fieldStyle(f field, value string) string {
	if f == m.focus {
		return focusStyle.Render(value)
	}
	return value
}

func (m *Model) storePath() string {
	if m.store == nil {
		return "（无配置存储）"
	}
	return m.store.Path()
}

func (m *Model) ipv6View() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("IPv6 检测") + "  ")
	if m.detecting {
		b.WriteString(yellowStyle.Render("检测中…"))
	} else if m.lastDetectAt.IsZero() {
		b.WriteString(dimStyle.Render("按 c 开始检测"))
	} else {
		b.WriteString(dimStyle.Render("上次检测: " + m.lastDetectAt.Format("15:04:05")))
	}
	b.WriteString("\n\n")

	header := fmt.Sprintf("  %-40s %-10s %-6s %-8s %-18s %s", "地址", "网卡", "stable", "可达", "探测方式", "延迟")
	b.WriteString(dimStyle.Render(header) + "\n")
	b.WriteString(dimStyle.Render("  "+strings.Repeat("─", 88)) + "\n")
	for _, a := range m.lastDetect {
		ip := a.IP.String()
		if a.Kind != ipv6.KindGUA {
			ip += " [" + string(a.Kind) + "]"
		}
		stable := "否"
		if a.Stable {
			stable = "是"
		}
		reachable := "否"
		if a.Reachable {
			reachable = "是"
		}
		latency := "-"
		if a.Latency > 0 {
			latency = a.Latency.String()
		}
		row := fmt.Sprintf("  %-40s %-10s %-6s %-8s %-18s %s",
			truncate(ip, 40), truncate(a.Interface, 10), stable, reachable,
			truncate(shortMethod(a.Method), 18), latency)
		switch {
		case a.Kind == ipv6.KindGUA && a.Reachable && a.Stable:
			b.WriteString(greenStyle.Render(row) + "\n")
		case a.Kind == ipv6.KindGUA && (!a.Reachable || !a.Stable):
			b.WriteString(yellowStyle.Render(row) + "\n")
		default:
			b.WriteString(dimStyle.Render(row) + "\n")
		}
		if a.Err != "" && a.Kind == ipv6.KindGUA {
			b.WriteString(dimStyle.Render("    └ "+truncate(a.Err, 96)) + "\n")
		}
	}
	if m.lastDetectErr != "" {
		b.WriteString("\n" + redStyle.Render("检测错误: "+m.lastDetectErr) + "\n")
	}
	if len(m.lastDetect) == 0 && !m.detecting {
		b.WriteString(dimStyle.Render("\n  暂无结果。按 c 检测本机 IPv6 地址。") + "\n")
	}
	return b.String()
}

func (m *Model) ddnsView() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("DDNS 更新") + "\n\n")
	b.WriteString(dimStyle.Render("域名: ") + m.cfg.Domain + "    " + dimStyle.Render("策略: ") + string(m.cfg.Policy) + "\n\n")

	cfIP := m.cfIP
	if cfIP == "" && m.cfErr == "" {
		cfIP = "加载中…"
	}
	b.WriteString(m.statusLine("Cloudflare AAAA", cfIP))
	if m.cfErr != "" {
		b.WriteString(redStyle.Render("  读取失败: "+m.cfErr) + "\n")
	}
	localIP, source := m.candidate()
	b.WriteString(m.statusLine("本机候选 IP", localIP+" ("+source+")"))
	b.WriteString(m.statusLine("手动 IPv6", displayIP(m.cfg.Address)))
	b.WriteString("\n")

	if m.updating {
		b.WriteString(yellowStyle.Render("  正在更新…") + "\n")
	} else {
		b.WriteString(dimStyle.Render("  按 u 执行一次 Detect + DDNS 更新") + "\n")
	}
	if m.lastResultErr != "" {
		b.WriteString(redStyle.Render("  上次更新失败: "+m.lastResultErr) + "\n")
	} else if !m.lastResult.Timestamp.IsZero() {
		r := m.lastResult
		b.WriteString(m.statusLine("上次时间", r.Timestamp.Format("2006-01-02 15:04:05")))
		b.WriteString(m.statusLine("旧 IP", displayIP(r.OldIP)))
		b.WriteString(m.statusLine("新 IP", displayIP(r.NewIP)))
		b.WriteString(m.statusLine("结果", resultText(r)))
	}
	return b.String()
}

func (m *Model) inboundView() string {
	var b strings.Builder
	b.WriteString(accentStyle.Render("入站可达性检测"))
	b.WriteString("  " + dimStyle.Render("从 Cloudflare 边缘主动 TCP 连入，真实验证外网可达") + "\n\n")

	ip, source := m.candidate()
	ipDisplay := displayIP(ip)
	if ip == "" || ip == "-" {
		ipDisplay = redStyle.Render("无可用地址（先按 c 检测或配置手动 IPv6）")
	}
	b.WriteString(m.statusLine("目标 IPv6", ipDisplay))
	if source != "" {
		b.WriteString(m.statusLine("地址来源", source))
	}
	b.WriteString(m.statusLine("目标域名", inbound.TargetHost))
	b.WriteString(m.statusLine("Worker", m.inboundWorkerURL))

	portStyle := lipgloss.NewStyle()
	if m.focus == fieldPort {
		portStyle = focusStyle
	}
	b.WriteString("  " + fmt.Sprintf("%-16s", "端口") + portStyle.Render(m.inputs[7].View()) + "\n\n")

	switch {
	case m.inboundChecking:
		b.WriteString(yellowStyle.Render("  正在从 Cloudflare 边缘探测…") + "\n")
	case m.inboundErr != "":
		b.WriteString(redStyle.Render("  检测失败: "+m.inboundErr) + "\n")
	case m.inboundAt.IsZero():
		b.WriteString(dimStyle.Render("  尚未检测，按 i 开始") + "\n")
	default:
		r := m.inboundResult
		if r.Reachable {
			b.WriteString(greenStyle.Render("  ✓ 外网可入站 (reachable)") + "\n")
		} else {
			b.WriteString(redStyle.Render("  ✗ 不可入站 (unreachable)") + "\n")
		}
		b.WriteString(m.statusLine("延迟", formatLatency(r.Latency)))
		b.WriteString(m.statusLine("时间", m.inboundAt.Format("2006-01-02 15:04:05")))
		if r.Err != "" {
			b.WriteString(redStyle.Render("  错误: "+truncate(r.Err, 90)) + "\n")
		}
		if from, ok := r.Raw["from"].(string); ok && from != "" {
			b.WriteString(m.statusLine("探测节点", from))
		}
		if remote, ok := r.Raw["remoteAddress"].(string); ok && remote != "" {
			b.WriteString(m.statusLine("远端地址", remote))
		}
	}
	b.WriteString("\n" + dimStyle.Render("  提示：按 i 触发一次异步检测；结果由 Worker 从 CF 边缘返回。"))
	return b.String()
}

func formatLatency(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return d.String()
}

func colorizeResult(r ddns.Result) string {
	text := resultText(r)
	if r.Updated {
		return greenStyle.Render(text)
	}
	if r.Message != "" {
		return yellowStyle.Render(text)
	}
	return dimStyle.Render(text)
}

func resultText(r ddns.Result) string {
	msg := r.Message
	if r.Updated {
		msg = "已更新: " + displayIP(r.OldIP) + " → " + displayIP(r.NewIP)
	}
	return msg
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
