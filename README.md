# v6ddns

一个跨平台的 **Cloudflare IPv6 DDNS** 小工具：带 Fyne 原生 GUI + 系统托盘，能检测本机 IPv6 是否公网可达，并把可达的稳定地址自动写进 Cloudflare 的 AAAA 记录。GUI 关闭窗口只隐藏到托盘，后台持续更新；也保留 `--daemon` / `--once` 给 cron/systemd 用。

## 它解决什么现成工具没解决的问题

普通 DDNS 工具通过 HTTP 服务（`ipify`、`icanhazip`）查询"我的公网 IP"。当机器上跑着 **Clash/FlClash/Surge 的 TUN 模式**时，这类查询会被代理骗——本机的 `2000::/3` 路由被劫持到虚拟网卡，探测服务看到的是代理出口，不是你真实的 IPv6。

v6ddns 换个思路：**枚举本机所有 IPv6 地址 → 把探测流量的源地址绑定到每个地址 → 看能否直连公共 IPv6 节点**。这样 TUN 路由就骗不了它，能准确找出物理网卡上真正公网可达的地址，并区分 stable（EUI-64 / 非 temporary）和临时隐私地址。

实测（Intel Mac + FlClash TUN）：
```
2408:8262:c7f:6c4f:2a:85cb:1452:5d19  en0   GUA  stable=true  reachable=true  tcp-source-bind  32ms
fdfe:dcba:9876::1                       utun4 ULA  stable=true  reachable=false not-gua   ← FlClash fake-ip，被正确排除
```

## 功能

- **Fyne 原生 GUI**：五个标签页（总览 / 配置 / IPv6 检测 / DDNS / 入站检测），Token 用密码框显示，配置存 0600 权限
- **系统托盘**：关闭窗口只隐藏；托盘菜单有「显示窗口 / 立即更新 / 状态 / 退出」；更新成功/失败发系统通知
- **开机自启动**：配置页勾选开启（默认关闭），自动注册 LaunchAgent（macOS）/ 注册表 Run 项（Windows）/ XDG autostart（Linux），以 `--tray` 模式启动并驻留托盘
- **IPv6 检测页**：表格列出所有地址，标注 GUA/ULA/link-local、stable、可达性、探测方式、延迟
- **DDNS 引擎**：对比 Cloudflare 当前 AAAA 与本机地址，变了才更新；失败绝不删除/破坏现有记录；拒绝 ULA/link-local/文档段/Cloudflare anycast
- **入站检测页**：通过 Cloudflare Worker 从公网主动 TCP 连入本机，验证真正的外网入站可达性

## 安装 / 构建

### 从 GitHub Release 下载（推荐）
到 [Releases](../../releases) 下载对应平台的压缩包，解压即用：
- `v6ddns-<版本>-linux-amd64.tar.gz`
- `v6ddns-<版本>-darwin-amd64.tar.gz`（Intel Mac）
- `v6ddns-<版本>-darwin-arm64.tar.gz`（Apple Silicon Mac）
- `v6ddns-<版本>-windows-amd64.zip`

Fyne 需要 CGO 和原生 GUI 库；构建环境需 Go 1.23+、C 编译器和平台开发库（macOS 装 Xcode Command Line Tools，Linux 装 `libgl1-mesa-dev xorg-dev`）。

> **macOS 未签名**：首次运行可能被 Gatekeeper 拦截。右键 → 打开，或执行 `xattr -d com.apple.quarantine ./v6ddns` 后即可正常打开。
>
> **Linux 通知**：系统通知依赖通知守护进程（如 GNOME 自带）；无桌面环境时通知不会显示，但托盘和日志仍正常。

### 本地构建
```bash
export PATH=/tmp/go-toolchain/go/bin:$PATH   # 若系统未装 Go
go build -o v6ddns .
```

## 使用

### 1. 准备 Cloudflare API Token
https://dash.cloudflare.com/profile/api-tokens → Create Token → 权限 `Zone:DNS:Edit` + `Zone:Zone:Read`，Zone Resources 选你的域名。同时记下域名概览页的 **Zone ID**。

### 2. 启动 GUI
```bash
./v6ddns
```
- 到「配置」页填 Token / Zone ID / 域名等，点「保存」
- 到「IPv6 检测」页点「检测 IPv6」，确认真实网卡地址显示 `可达=true`
- 到「DDNS」页点「立即更新」，确认写入了正确地址
- 到「入站检测」页填端口（默认 38080）点「开始检测」，确认公网能连进来
- 需要开机自启：在「配置」页勾选「开机自启动」并保存

### 3. 托盘与后台
- 点窗口 X：只隐藏到托盘，进程继续在后台按间隔更新
- 托盘图标菜单：显示窗口 / 立即更新 / 状态 / 退出
- 更新成功或失败会弹系统通知，托盘「状态」项显示当前 AAAA 和上次更新时间

命令行模式（无 GUI，适合 cron / systemd / 路由器）：
```bash
./v6ddns --daemon              # 按 config 里的 interval（默认 5m）循环
./v6ddns --once                # 更新一次后退出
./v6ddns --tray                 # 以托盘模式启动（自启动项用，平时不用手动敲）
./v6ddns --config /path/to/cfg # 指定配置文件
./v6ddns --icmp                # 额外尝试 ICMPv6 探测（需 root/管理员，失败自动回退 TCP）
```

配置保存在：`~/Library/Application Support/v6ddns/config.yaml`（macOS）、`~/.config/v6ddns/config.yaml`（Linux）、`%AppData%\v6ddns\config.yaml`（Windows）。

### 配置示例
```yaml
api_token: your-token-here
zone_id: 0123456789abcdef0123456789abcdef
domain: mac.example.com
ttl: 1              # 1 = automatic
proxied: false      # 直连必须灰云；橙云会隐藏真实 IP 且只代理 HTTP(S)
interface_name: en0 # 只检测这块网卡；留空则全部
interval: 5m
policy: stable-auto # manual | stable-auto | any-reachable
address: ""         # policy=manual 时填这里
probe_targets:      # 可选，覆盖默认探测目标
  - "[2400:3200::1]:443"
probe_timeout: 5s
```

### 地址选择策略（policy）
| 值 | 行为 |
|---|---|
| `stable-auto`（默认） | 选第一个 GUA + stable + 可达的地址 |
| `any-reachable` | 选第一个可达 GUA（包括临时地址，有警告） |
| `manual` | 用 `address` 字段指定的地址，不探测 |

## 探测原理

### 出站可达（IPv6 检测页）
1. 枚举网卡 IPv6（`ifconfig` / `ip -6 addr` / `netsh`），分类 GUA/ULA/link-local，按 flags 判断 stable vs temporary
2. 对每个 GUA 做源地址绑定的 TCP connect（绑到 `[2400:3200::1]:443`，阿里 DNS，实测国内通；备选 Cloudflare DNS）。不需要 root
3. `--icmp` 时先尝试 raw-socket ICMPv6，失败自动回退 TCP
4. 引擎过滤：只发布 `IsPublicGUA()` 且非 Cloudflare anycast 的地址
5. 这一步只证明"本机能用这个地址连出去 + IP 真实"，**不能证明外网能连进来**

### 入站可达（入站检测页）
GUI 第 5 页集成了一个部署在 Cloudflare 边缘的探针（`https://v6probe.254253.xyz`，源码见 `probe-worker/`）：
- 先把 `target.254253.xyz` 的 AAAA 记录指向待测 IPv6（通过 Cloudflare API）
- 再让 Worker 从 CF 边缘主动 TCP 连接 `target.254253.xyz:<端口>`
- `reachable: true` = **公网真的能连进你的机器**

这是真正的入站验证，出站探测做不到。实测本实例：`reachable=true, latency≈380ms`。

> 注意：Cloudflare Workers 的 `connect()` 只接受域名、不接受 IP 字面地址，所以探针连的是专门的 `target.254253.xyz` 域名，而不是直接连 IPv6。详见 `probe-worker/README.md`。

## 测试

```bash
gofmt -l . && go vet ./... && go test ./...
```
50 个测试用例覆盖：地址分类、配置读写/掩码、探测解析、Cloudflare API mock、DDNS 决策（更新/跳过/无地址/失败/策略/过滤）、入站探针（响应解析、fake-ip 绕过、参数校验）。

## 已知取舍

- 不做 IPv4 DDNS、多域名批量、Cloudflare Tunnel、Web UI（范围外）
- 历史 IP 不落盘：引擎每轮读 Cloudflare 真实记录来比较，同样能检测手改，且少一个状态文件
- `--icmp` 在本机需要 root，默认关闭；TCP 探测已够用
- 发布平台收敛到 4 个主流架构（linux-amd64 / darwin-amd64 / darwin-arm64 / windows-amd64）；其他架构请自行 `go build`
- Go 未系统安装时，临时工具链在 `/tmp`，重启后需重新下载
