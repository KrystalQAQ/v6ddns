# v6ddns — IPv6 DDNS TUI 工具规格

## 一句话定位
跨平台的 Cloudflare IPv6 DDNS **守护进程**：启动时是 TUI，可配置、可检测本机 IPv6 公网可达性、可手动更新；`--daemon` 模式后台常驻定时更新。Go 单文件二进制，Bubble Tea TUI。

## 用户与场景
- 家和实验室有 IPv6，域名托管在 Cloudflare，要把域名 AAAA 记录自动指向本机公网 IPv6。
- **关键环境特征**：用户 Mac 上跑着 FlClash 的 TUN 模式（root 进程），路由表里 `2000::/3 → utun4`（fake-ip 段 `fdfe:dcba:9876::1`）。HTTP 探测会拿到假 IP（`42.200.231.232`）。但物理网卡 `en0` 上有真公网 IPv6 `2408:8262:c7f:6c4f:2a:85cb:1452:5d19`，从该源地址 `ping6 2400:3200::1` 通（33ms）。
- **因此**：DDNS 引擎不能只靠 HTTP 探测公网 IP；必须能枚举本机全局单播地址、判断哪个是 stable、绑定源地址做可达性探测，绕过 TUN 假象。

## 功能需求（P0）

### F1. IPv6 检测（核心差异点）
- 枚举所有网卡的 IPv6 地址，分类：GUA (2000::/3) / ULA (fc00::/7) / link-local (fe80::/10) / loopback。
- 标注 stable vs temporary（读 `/proc/net/if_inet6` 或 `net.InterfaceAddrs` + 系统命令；macOS 用 `ifconfig`/`networksetup`，Linux 用 `ip -6 addr`，Windows 用 `netsh`；识别 RFC 4941 temporary、SLAAC EUI-64 stable）。
- 对每个 GUA 地址做**源地址绑定**的公网可达性探测：
  - ICMPv6 ping 公共目标（如 `2400:3200::1` 阿里 DNS、`2606:4700:4700::1111` CF DNS），绑定源地址；需要 raw socket 权限，失败时回退到 TCP 连接（绑定源地址 TCP connect 到 `[2606:4700:4700::1111]:443`）。
  - HTTP 探测仅作为**辅助参考**，明确标注"可能被代理污染"，不单独作为写记录的依据。
- TUI 检测结果表格：地址 / 网卡 / stable? / 可达? / 探测方式 / 延迟。

### F2. Cloudflare DDNS 引擎
- API Token 认证（权限 `Zone.DNS.Edit` + `Zone.Zone.Read`）。
- 配置：Zone ID、域名（FQDN）、TTL（默认 1=auto）、proxied（默认 false，直连必须灰云）。
- 更新流程：读当前 AAAA → 与目标比较 → 相同跳过，不同则 PATCH；失败不动记录。
- 目标地址选择策略（可配置优先级）：
  1. 用户手动指定的 IPv6（TUI 里填）
  2. 本机 stable 且公网可达的 GUA（自动）
  3. 本机任意可达 GUA（自动，带警告）
- 拒绝把 ULA / link-local / Cloudflare anycast 段写进记录。
- 持久化历史 IP 到 `data/state.json`（借鉴 qdm12），用于检测手动改动 + 显示历史。

### F3. TUI（Bubble Tea）
- 主界面分栏/分页：
  - **Dashboard**：当前配置摘要、上次检测结果、上次 DDNS 状态、最近日志（滚动）。
  - **Config**：表单编辑 API Token（密码输入）、Zone ID、域名、网卡选择、更新间隔、目标地址策略。保存到 `config.yaml`（用 gopkg.in/yaml.v3）。
  - **IPv6 Check**：触发检测，实时显示进度和结果表格。
  - **DDNS**：手动"立即更新"按钮，显示 Cloudflare 当前 IP vs 本机 IP vs 上次更新时间。
- 快捷键：`Tab` 切页、`Enter` 确认/`Esc` 返回、`q` 退出、`r` 刷新、`u` 更新、`c` 检测。
- 配置保存到用户配置目录（`os.UserConfigDir()`/v6ddns/），不写二进制旁边（Windows 兼容）。
- Token 不明文显示在界面（用 `•` 掩码），存文件时权限 0600。

### F4. 守护模式
- `v6ddns --daemon`：无 TUI，按配置间隔（默认 5m）循环检测 + 更新，日志到 stdout。
- `v6ddns --once`：检测 + 更新一次后退出（给 cron/systemd 用）。
- 默认（无参数）：TUI。
- `--config PATH` 指定配置文件。

## 技术约定
- Go 1.22+；依赖：`github.com/charmbracelet/bubbletea`, `bubbles`, `lipgloss`, `gopkg.in/yaml.v3`, `golang.org/x/net/ipv6`（如需 raw socket）。
- 包结构（重要，便于并行开发）：
  ```
  v6ddns/
    main.go                  // CLI 入口、模式分发 (agent C)
    go.mod / go.sum
    SPEC.md
    internal/
      config/config.go       // 配置结构、加载/保存 (agent A)
      ipv6/detect.go         // F1: 地址枚举+分类+可达性探测 (agent A)
      cloudflare/api.go      // F2: Cloudflare API 封装 (agent B)
      ddns/engine.go         // F2: 更新决策引擎 (agent B)
      tui/model.go           // F3: Bubble Tea 主模型、分页 (agent C)
      tui/views.go           // F3: 各页 UI 渲染 (agent C)
      log/log.go             // 简单结构化日志 (agent A)
    cmd/                     // 可选
  ```
- 接口先行：各包对外暴露清晰接口，`main.go` 和 TUI 只依赖接口，便于 mock 测试。
- 跨平台：TCP connect 探测作为 ICMP 的回退（raw socket 需权限，Windows 上不可用）。
- 所有网络调用要有超时（默认 5s）。
- Token 永远不出现在日志里。

## 明确不做（P1/P2，别扩范围）
- 不做 IPv4 DDNS。
- 不做多域名批量（单域名即可；留好结构以后加）。
- 不做 Cloudflare Tunnel。
- 不做 WebUI。

## 交付与验收
- `go build ./...` 通过；`go vet` 无明显问题。
- `go test ./...` 有基础单测：IP 分类、配置读写、DDNS 决策逻辑（mock Cloudflare API）。
- 在用户 Mac 上实机跑 `--once`：能正确识别 en0 的 `2408:...` 为 stable 可达，不被 FlClash 假 IP 骗。
- README 写清楚三个模式的用法和权限需求。
