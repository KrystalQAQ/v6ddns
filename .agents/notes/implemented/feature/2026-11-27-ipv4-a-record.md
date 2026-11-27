# Agent Note: 用 ipv4_domain 维护一条公网 IPv4 的 A 记录

Status: implemented

## Problem

路由器 n1 上原本有一个独立的 `cloudflare-ddns` 容器负责把公网 IPv4 写到 `n1.254253.xyz` 的 A 记录。它跑在纯 IPv4 的 Docker bridge 上，而 n1 的 dnsmasq 为了绕开 Cloudflare API 的 IPv4 路径，把 `api.cloudflare.com` 固定解析到 IPv6 地址；容器没有 IPv6 路由，于是每一轮都报 `network is unreachable`，A 记录停在旧地址上很久没人发现。

用户希望由 v6ddns 自己维护这条 A 记录：配置一个域名，定期把本机公网 IPv4 更新上去，不再依赖另一个容器。

## Decision

在顶层配置增加可选的 `ipv4_domain`：

```yaml
ipv4_domain: n1.254253.xyz
```

- **检测**：新增 `internal/ipv4`。`Detector` 依次请求 `ipv4.icanhazip.com`、`checkip.amazonaws.com`、`ifconfig.me/ip`，HTTP transport 的 `DialContext` 固定为 `tcp4`，避免双栈主机把请求发到 IPv6 出口。返回值必须是 `Usable` 的公网 IPv4：排除私有、回环、链路本地、CGNAT（100.64/10）以及 TEST-NET/benchmark/reserved 段。`Proxy` 显式设为 nil，答案必须来自本机出口而不是环境代理。
- **Cloudflare 客户端**：`GetRecord` 和 `CreateRecord` 增加 `recordType` 参数，新增 `RecordTypeA`；空类型仍默认 AAAA，未知类型在本地直接报错。`UpdateRecord` 与类型无关，不改。
- **引擎**：`RunOnce` 在 IPv6 记录之后处理可选的 A 记录，结果追加到 `Result.Records`（`Type=A`、`Source=public-ipv4`）。同名 A/AAAA 允许共存，不做去重。`Result.Updated` 任一记录变化即为 true；摘要行数改为按实际记录数判断。
- **不接入 require_inbound**：现有 Worker 探测依赖按地址命名的 AAAA 探测记录，无法描述 IPv4 目标；IPv4 入站通常还受上游 NAT 限制。检测失败或地址不可用时只打 WARN 并保持记录不变，不把整轮标记为失败。
- **控制台**：配置页增加「IPv4 域名（可选）」输入框；`configPayload` 增加 `ipv4_domain`；总览页由三张状态卡改为四张，「IPv6 记录」与「IPv4 记录」并列（IPv4 卡显示 A 记录最新地址或「未配置」）；`Status` 增加 `ipv4_domain` 供页面判断是否启用；托管记录表增加「类型」列（A/AAAA 徽章）并补上「说明」列表头；把 `public-ipv4` 显示为「公网 IPv4」，翻译 `A record updated/created`，并把动态汇总（`N records unchanged` / `N records: ...`）本地化。

## Alternatives considered

1. **继续维护旧容器，改用 host network 或修 Docker IPv6。** 能修好这一条 A 记录，但仍要维护第二个 DDNS 工具、第二套日志和配置；用户已经要求统一到 v6ddns。
2. **把 IPv4 也塞进 `records`，用 `source: public`。** 需要给 `RecordSpec` 增加类型维度，并让 policy/interface/MAC 这些 IPv6 专用字段对 A 记录无意义，配置面更大；顶层一个 `ipv4_domain` 已足够表达“本机公网 IPv4 → 指定域名”。
3. **通过上游路由器 API/UPnP 读取 WAN IPv4。** 更接近“真实出口”，但依赖具体路由器型号和凭据，不可移植；公共 echo 服务在目标环境已验证返回同一个 211.158.47.96。
4. **给 A 记录也做入站探测。** 需要新的按 IPv4 命名的探测记录和 Worker 侧 IPv4 回连，而本机 IPv4 入站很可能被上游 NAT 挡住；收益低、复杂度高。

## Consequences

- v6ddns 现在同时维护 AAAA 和可选的 A 记录，旧容器可以停用；日志、控制台、错误处理都在同一条链路上。
- IPv4 检测依赖三个外部 echo 服务；它们全挂时只打 WARN，下一轮重试。检测到的是“出口看到的 IPv4”，如果本机流量被透明代理接管，可能拿到代理出口地址。
- `require_inbound` 的语义明确为“只校验 AAAA”；A 记录的更新不做入站确认。
- Cloudflare 客户端接口多了类型参数，所有调用点和测试桩都要跟着改。

## Testing

- `internal/ipv4`：首个可用答案、跳过坏响应、全部失败、context 取消、`Usable` 特殊网段表。
- `internal/cloudflare`：A/AAAA 查询类型、未知类型本地报错。
- `internal/ddns`：A 记录更新、创建、未变化、检测失败四条路径。
- `internal/config`：`ipv4_domain` 解析归一化与校验。
- `gofmt -l`、`go vet ./...`、`go test ./...`；部署后在 n1 观察 `/root/logs/v6ddns.log` 的 `A record updated` 以及公共 DNS 的 A 记录值。
