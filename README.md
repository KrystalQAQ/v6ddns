# v6ddns

一个跨平台的 **Cloudflare IPv6 DDNS** 小工具：常驻系统托盘，管理界面是一个只监听本机的 Web 控制台（`127.0.0.1:38081`）。它能检测本机 IPv6 是否公网可达，并把可达的稳定地址自动写进 Cloudflare 的 AAAA 记录。控制台用浏览器打开，Tauri/Fyne 那套 WebView/OpenGL 依赖统统不需要；空闲时常驻内存约 25MB。

## 它解决什么现成工具没解决的问题

普通 DDNS 工具通过 HTTP 服务（`ipify`、`icanhazip`）查询"我的公网 IP"。当机器上跑着 **Clash/FlClash/Surge 的 TUN 模式**时，这类查询会被代理骗——本机的 `2000::/3` 路由被劫持到虚拟网卡，探测服务看到的是代理出口，不是你真实的 IPv6。

v6ddns 换个思路：**枚举本机所有 IPv6 地址 → 把探测流量的源地址绑定到每个地址 → 看能否直连公共 IPv6 节点**。这样 TUN 路由就骗不了它，能准确找出物理网卡上真正公网可达的地址，并区分 stable（EUI-64 / 非 temporary）和临时隐私地址。

实测（Windows + FlClash TUN）：
```
240e:b30:222d:1d00::22e              WLAN  GUA  stable=true  reachable=true  tcp-source-bind  34ms
fdfe:dcba:9876::1                    FlClash ULA stable=true reachable=false not-gua   ← fake-ip，被正确排除
```

## 功能

- **本机 Web 控制台**：总览 / IPv6 地址 / DDNS / 入站检测 / 配置五个页面，深色、浅色、跟随系统三档主题；无需安装任何前端依赖，静态资源全部嵌进二进制
- **系统托盘**：左键打开控制台；菜单里有「打开控制台 / 立即更新 / 状态 / 地址 / 域名 / 退出」
- **开机自启动**：配置页勾选开启，自动注册 LaunchAgent（macOS）/ 注册表 Run 项（Windows）/ XDG autostart（Linux），以 `--tray` 模式启动且不打开浏览器
- **IPv6 检测页**：表格列出所有地址，标注 GUA/ULA/link-local、stable、可达性、探测方式、延迟
- **DDNS 引擎**：对比 Cloudflare 当前 AAAA 与本机地址，变了才更新；失败绝不删除/破坏现有记录；拒绝 ULA/link-local/文档段/Cloudflare anycast
- **入站检测页**：通过 Cloudflare Worker 从公网主动 TCP 连入本机，验证真正的外网入站可达性
- **无 UI 模式**：`--daemon` / `--once` 供 cron、systemd、路由器使用，内存约 25MB

## 控制台的安全边界

控制台能改 Cloudflare Token，所以它**只绑定 `127.0.0.1`**，并且：

- 每个进程随机生成 32 字节令牌，注入页面 `meta`，所有 API 请求都要带 `X-V6DDNS-Token`，常量时间比较
- 校验 `Host`，只接受 `127.0.0.1`、`localhost`、`::1` 及其端口，挡住 DNS rebinding
- 修改类请求校验 `Origin`；页面带 CSP、`X-Frame-Options: DENY`、`nosniff`、`no-referrer`，并且 `Cache-Control: no-store`
- 公网端口（`listen_port`，默认 38080）只用于入站探测，不提供任何管理接口

## 安装 / 构建

### 从 GitHub Release 下载（推荐）
到 [Releases](../../releases) 下载对应平台的压缩包，解压即用：
- `v6ddns-<版本>-linux-amd64.tar.gz`
- `v6ddns-<版本>-darwin-amd64.tar.gz`（Intel Mac）
- `v6ddns-<版本>-darwin-arm64.tar.gz`（Apple Silicon Mac）
- `v6ddns-<版本>-windows-amd64.zip`

Windows / Linux 构建不需要 CGO，也不需要 GTK/OpenGL 开发库。macOS 的托盘走 Cocoa，需要 Xcode Command Line Tools。

> **macOS 未签名**：首次运行可能被 Gatekeeper 拦截。右键 → 打开，或执行 `xattr -d com.apple.quarantine ./v6ddns` 后即可正常打开。

### 本地构建
```bash
go build -o v6ddns .
```

## 使用

### 1. 准备 Cloudflare API Token
https://dash.cloudflare.com/profile/api-tokens → Create Token → 权限 `Zone:DNS:Edit` + `Zone:Zone:Read`，Zone Resources 选你的域名。同时记下域名概览页的 **Zone ID**。

### 2. 启动
```bash
./v6ddns
```
进程会启动托盘、开始监听公网端口，并自动打开 <http://127.0.0.1:38081/>。如果 38081 被占用，会临时换一个随机端口，URL 会打印在终端。

- 到「配置」页填 Token / Zone ID / 域名等，点「保存并应用」
- 到「IPv6 地址」页点「检测 IPv6」，确认真实网卡地址显示「可达」
- 到「DDNS」页点「立即更新」，确认写入了正确地址
- 到「入站检测」页点「从公网检测」，确认公网能连进来
- 需要开机自启：在「配置」页勾选「开机自启动」并保存

### 3. 托盘与后台
- 关闭浏览器标签不会退出程序；进程继续按间隔更新
- 托盘左键打开控制台；右键菜单：打开控制台 / 立即更新 / 状态 / 退出
- 日常管理都在浏览器里完成，托盘只负责「在不在」和「地址是多少」

命令行模式（无 UI，适合 cron / systemd / 路由器）：
```bash
./v6ddns --daemon              # 按 config 里的 interval（默认 5m）循环
./v6ddns --once                # 更新一次后退出
./v6ddns --tray                # 托盘模式启动，但不自动打开浏览器（自启动项用）
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
interface_name: ""  # 只检测这块网卡；留空则全部
interval: 5m
policy: stable-auto # manual | stable-auto | any-reachable
address: ""         # policy=manual 时填这里
probe_targets:      # 可选，覆盖默认探测目标
  - "[2400:3200::1]:443"
probe_timeout: 5s
listen_port: 38080  # 应用启动后监听的 TCP 端口（入站检测复用）
admin_port: 38081   # 本机控制台端口，只绑定 127.0.0.1
inbound_worker: https://v6probe.254253.xyz  # 可选，入站检测 Worker
```

### 地址选择策略（policy）
| 值 | 行为 |
|---|---|
| `stable-auto`（默认） | 选第一个 GUA + stable + 可达的地址 |
| `any-reachable` | 选第一个可达 GUA（包括临时地址，有警告） |
| `manual` | 用 `address` 字段指定的地址，不探测 |

## 探测原理

### 出站可达（IPv6 地址页）
1. 枚举网卡 IPv6（`ifconfig` / `ip -6 addr` / `netsh`），分类 GUA/ULA/link-local，按 flags 判断 stable vs temporary
2. 对每个 GUA 做源地址绑定的 TCP connect（绑到 `[2400:3200::1]:443`，阿里 DNS，实测国内通；备选 Cloudflare DNS）。不需要 root
3. `--icmp` 时先尝试 raw-socket ICMPv6，失败自动回退 TCP
4. 引擎过滤：只发布 `IsPublicGUA()` 且非 Cloudflare anycast 的地址
5. 这一步只证明"本机能用这个地址连出去 + IP 真实"，**不能证明外网能连进来**

### 入站可达（入站检测页）
应用启动时就会在 `listen_port`（默认 38080）上监听一个只读状态页，不需要额外启动服务。
「入站检测」页集成了一个部署在 Cloudflare 边缘的探针（`inbound_worker`，默认 `https://v6probe.254253.xyz`，源码见 `probe-worker/`）：
- 先把本机 IPv6 写入配置的 `domain`（必须灰云），域名是必填项，不再使用硬编码的 target 子域
- 再让 Worker 从 CF 边缘主动 TCP 连接 `domain:<listen_port>`
- `reachable: true` = **公网真的能连进你的机器**

这是真正的入站验证，出站探测做不到。实测本实例：`reachable=true, latency≈250ms`。

可选的「入站闸门」（`require_inbound`）会在写入主域名之前先验证候选地址：引擎为每个候选地址创建一次性的 `v6-<地址>.<probe_base>` AAAA 记录，Worker 实测通过后才更新主域名；`probe_base` 留空即使用主域名。每条地址使用唯一的验证名，避免 DNS 缓存让 Worker 验证到旧地址。

> 注意：Cloudflare Workers 的 `connect()` 只接受域名、不接受 IP 字面地址，所以探针必须连一个解析到本机 IPv6 的域名。详见 `probe-worker/README.md`。

## 测试

```bash
gofmt -l . && go vet ./... && go test ./...
```

测试覆盖：地址分类、配置读写/校验/掩码、探测解析、Cloudflare API mock、DDNS 决策（更新/跳过/无地址/失败/策略/过滤）、入站探针（响应解析、fake-ip 绕过、参数校验）、控制台（令牌、Host/Origin 守卫、配置往返、日志游标）与日志环形缓冲。

## 已知取舍

- 不做 IPv4 DDNS、多域名批量、Cloudflare Tunnel、可远程访问的 WebUI（本机控制台不属于此类）
- 历史 IP 不落盘：引擎每轮读 Cloudflare 真实记录来比较，同样能检测手改，且少一个状态文件
- `--icmp` 在本机需要 root，默认关闭；TCP 探测已够用
- 发布平台收敛到 4 个主流架构（linux-amd64 / darwin-amd64 / darwin-arm64 / windows-amd64）；其他架构请自行 `go build`
- 控制台不提供 TLS：它只活在本机回环上，浏览器访问 `127.0.0.1` 本身被视为安全上下文
