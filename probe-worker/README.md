# v6-inbound-probe

部署在 Cloudflare 边缘的 **IPv6 入站可达性探针**。从外部主动 TCP 连接你的机器，真实验证"公网能否连进来"——本机 `tcp-source-bind` 出站探测做不到这一点。

## 已部署（本实例）

- **Worker URL**: `https://v6probe.254253.xyz`
- **Route**: `v6probe.254253.xyz/*` → Worker `v6-inbound-probe`
- **占位 DNS**: `v6probe.254253.xyz` A 记录（proxied，route 匹配需要）
- **目标域名**: 由 v6ddns 配置的 `domain` 提供；开启入站闸门时，程序会为每个候选地址动态创建 `v6-<地址>.<probe_base>` 的 AAAA 记录（DNS only）

## 实测结果（2026-11-20）

```
本机 IPv6 服务开着: reachable=true, latencyMs=361   ← 外网能连进来 ✅
本机服务关掉:       reachable=false                  ← 对照，确认不是假阳性 ✅
```

## 关键发现（踩坑记录）

1. **Workers `connect()` 只接受域名，不接受 IP 字面地址**（IPv4/IPv6 字面都在 0-1ms 被拒，报 "cannot connect to the specified address"）。实测：`ipv6.google.com:443` 通（34ms），`2400:3200::1:443` 和 `1.1.1.1:443` 都不通。所以 Worker 必须连一个解析到你 IPv6 的**域名**（v6ddns 里配置的 `domain`，或闸门生成的 `v6-<地址>.<probe_base>`）。
2. **Route pattern 必须带 `/*`**，否则带 query string 的请求（`?host=...`）不匹配，会得到 522。
3. **Route 需要 proxied DNS 记录**：域/子域必须有 DNS 记录才能被 CF 代理并触发 Worker。wildcard CNAME 存在时，具体子域的记录+route 仍可工作。
4. **FlClash fake-ip**：本机 `dig v6probe.254253.xyz` 会返回 `198.18.0.193`（假 IP）。测试时用 `curl --resolve v6probe.254253.xyz:443:104.21.13.231` 绕过，或从手机/其他网络访问。

## 用法

### 验证某个 IPv6 的入站可达性

1. 确保你的域名（例如 `home.example.com`）的 AAAA 记录指向要测试的 IPv6。GUI 的「入站检测」会自动完成这一步；也可以手动用 CF API 或 dashboard 修改。
2. 在本机起监听服务（绑到某个端口，比如 38080；GUI 启动后会自动监听 `listen_port`）：
   ```bash
   python3 -c "
   import http.server, socket
   class S(http.server.HTTPServer):
       address_family = socket.AF_INET6
   S(('你的IPv6', 38080), http.server.SimpleHTTPRequestHandler).serve_forever()
   "
   ```
3. 从**外部网络**（手机流量，或本机用 `--resolve` 绕过 fake-ip）调用 Worker：
   ```bash
   curl --resolve v6probe.254253.xyz:443:104.21.13.231 \
     'https://v6probe.254253.xyz/?host=home.example.com&port=38080&timeout=8000'
   ```

### 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `host` | 必填 | **域名**（不能是 IP 字面，Workers 限制） |
| `port` | 443 | 1-65535，不能是 25 |
| `timeout` | 6000 | 超时毫秒，范围 100-15000 |

返回 `reachable: true` = 外网可入站；`false` = 检查光猫/运营商防火墙、本机防火墙、服务是否监听。

## 重新部署

```bash
cd probe-worker
npx wrangler deploy      # 用 OAuth 登录态（注意：不要 export CLOUDFLARE_API_TOKEN，权限不足会失败）
```
