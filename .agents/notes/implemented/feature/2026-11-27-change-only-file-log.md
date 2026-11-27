# Agent Note: 日志持久化到文件并且只记录变更

Status: implemented

## Problem

daemon 每 5 分钟跑一轮检测，无论地址有没有变化都会打两行 INFO：engine 的 `IPv6 unchanged, skipped` 和 daemon 的 `ddns result updated=false`。在路由器上这两行很快把 syslog 环形缓冲区占满，真实的地址变更和探测错误被挤掉；缓冲区本身在内存里，重启就丢。排障时既看不到历史变更，也难以从当前缓冲区里挑出真正的异常。

用户的要求有两条：日志要落盘、跨重启保留；落盘内容只记录变更，不要心跳。

## Decision

INFO 的语义收窄为「世界发生变化，或需要人关注」：

- `internal/ddns/engine.go` 的 `IPv6 unchanged, skipped` 与 `neighbour address selected` 降到 DEBUG。
- `internal/daemon/daemon.go` 只在 `result.Updated == true` 时用 INFO 记录 `ddns result`，未变化时降为 DEBUG。
- AAAA 创建/更新、`no usable IPv6 address`、入站探测失败、启停、配置保存、手动操作仍保持 INFO/WARN/ERROR。

持久化由 `V6DDNS_LOG_FILE` 环境变量启用，而不是写进 `config.yaml`：

- `internal/log/file.go` 提供 `NewFile(path, maxBytes)`：追加写、权限 `0600`、自动创建父目录、超过 5 MiB 轮转为 `path+".1"`（只留一份备份）。
- `main.go` 的 `newLogger` 把 supervisor 的 stdout/stderr、控制台环形缓冲（见 [托盘 + Web 控制台](../architecture/2026-11-20-tray-loopback-web-console.md)）和可选文件用 `io.MultiWriter` 串起来，桌面模式与 `--daemon --console` 共用。
- 文件 sink 与控制台共用同一个 INFO 阈值和同一份 secret 脱敏列表，文件里不会出现 API Token 或控制台密码。
- 部署侧在 procd 的 `procd_set_param env` 里加 `V6DDNS_LOG_FILE=/root/logs/v6ddns.log`；`/root` 在 overlay 上，`/var` 是 tmpfs，不能放。

## Alternatives considered

1. **用 OpenWrt logd/rsyslog 把 syslog 落盘。** 这会持久化所有守护进程的日志，心跳仍然存在；靠外部 grep 过滤既脆弱又占空间，桌面端和其他发行版也拿不到同样能力。
2. **在 `config.yaml` 加 `log_file` 并在控制台表单编辑。** 控制台保存时会按表单字段整体写回，新字段必须同步改前端，否则每次保存都被清零；日志路径是部署属性（procd/systemd 决定），不是用户配置，放环境变量更合适。
3. **保留 unchanged 到文件，读取时过滤。** 文件仍被心跳撑大，轮转会把真正的变更挤走，不满足「只记录变更」。
4. **交给外部 logrotate。** OpenWrt 默认不一定安装或配置；内置轮转让功能自包含，代价只是一份 `.1` 备份。

## Consequences

- 变更历史跨重启保留；正常运行时文件增长极慢，因为心跳轮次不写入。
- 控制台日志页也只剩变更与异常，查看时不再被心跳淹没。
- 失去每 5 分钟的心跳行；判断进程是否存活要看启动/停止行、状态页或 syslog 里的 procd 记录。
- 轮转只保留一份旧文件，持续告警风暴下最早的记录会被覆盖。
- DEBUG 目前没有运行时开关；临时需要看心跳时，只能改代码或看控制台状态里的时间戳。

## Testing

- `internal/log/file_test.go` 覆盖轮转、重开追加、重复 Close。
- `gofmt -l`、`go vet ./...`、`go test ./...`。
- 部署到 n1（OpenWrt + procd）后验证：`/root/logs/v6ddns.log` 生成、启动行写入、下一轮 unchanged 不再出现在文件和 syslog。
