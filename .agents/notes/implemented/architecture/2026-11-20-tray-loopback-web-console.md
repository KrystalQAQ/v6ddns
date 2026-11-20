# Agent Note: 用系统托盘 + 本机 Web 控制台替换 Fyne 桌面窗口

Status: implemented

## Problem

v0.2 的界面是 Fyne 原生窗口。实测常驻内存 335–340MB：Go 堆只有约 52MB，其中约 50MB 是 `go-text/typesetting` 的字体表与字形缓存，其余约 270MB 来自 Fyne 的 OpenGL/GLFW/原生控件层。Fyne 空窗口基线也有 185MB。界面本身也有明确缺陷：IPv6 表格列溢出重叠、日志为英文、部分卡片被裁切、配置表单铺满整屏、HiDPI 下字重过重。用户要求同时解决内存和界面质量，并选中了「托盘 + 本地 Web 控制台」路线。

这个决定需要守住两件事：一是进程仍要有原生托盘和开机自启，不能退化成必须开终端才能用的命令行工具；二是控制台能改 Cloudflare Token，因此绝不能暴露到局域网或公网。

## Decision

应用不再链接 Fyne。运行时由四层组成：

1. **`internal/service`** 持有唯一的长生命周期状态（配置、daemon、监听器、最近事件、地址列表、日志环形缓冲）。它只返回普通结构体，不知道 HTTP 或托盘的存在。所有人工操作（检测、更新、读记录、入站检测、保存配置）都通过它的方法完成，并复用与后台循环相同的 engine/factory。
2. **`internal/console`** 是唯一的 UI，绑定 `127.0.0.1:<admin_port>`（默认 38081）。静态资源用 `//go:embed` 打进二进制，无 npm、无前端构建。五个页面（总览 / IPv6 地址 / DDNS / 入站检测 / 配置）全部走 `/api/*` JSON。
3. **`internal/tray`** 只负责存在感：打开控制台、立即更新、显示状态/地址/域名、退出。Windows/Linux 走纯 Go 的 `fyne.io/systray`（CGO_ENABLED=0），macOS 走 Cocoa（cgo）。
4. **`main.go`** 默认启动 console + tray 并打开浏览器；`--tray` 用于自启动，不打开浏览器；`--daemon` / `--once` 保持无 UI，不启动 console。

控制台的安全不变量：

- listener **必须**只绑回环地址；`admin_port` 与 `listen_port` 在配置校验阶段强制不同。
- 所有 `/api/*`（除 `/api/health`）**必须**带 `X-V6DDNS-Token`；令牌是每进程 32 字节随机值，注入页面 `meta`，常量时间比较。
- `Host` 只允许 `127.0.0.1`、`localhost`、`::1` 且端口匹配；修改类请求的 `Origin` 也按同一规则校验。这是 DNS rebinding 的兜底。
- 页面响应带 CSP（`default-src 'self'`）、`frame-ancestors 'none'`、`X-Frame-Options: DENY`、`nosniff`、`no-referrer`、`no-store`。
- 公网 `listen_port` 继续只承担入站探测，不挂任何管理 API。

前端是无框架的 HTML/CSS/JS：

- 主题用 `color-scheme` + CSS `light-dark()`；`theme-init.js` 在样式表之前读 `localStorage`，避免闪白。三档选择是「跟随系统 / 浅色 / 深色」。
- 表格用容器查询在 720px 以下切成堆叠卡片，每格带 `data-label`。
- 所有服务端字符串用 `textContent` 写入 DOM，不拼 `innerHTML`。
- 复制按钮用 `command="--copy"` / `commandfor` 声明意图，但实际复制由 `click` 监听完成——Chromium 目前不会为自定义 `--` 命令派发 `command` 事件（实测 Chrome 157）。复制失败时回退到 `document.execCommand("copy")`。
- 日志用 `after` 游标轮询，只追加新行，DOM 最多保留 300 行。

发布构建的 CGO 策略：Linux/Windows 为 `CGO_ENABLED=0`，macOS 为 `1`；版本号通过 `-X main.version=<tag>` 注入，侧栏和 `/api/status` 会显示。

## Alternatives considered

- **保留 Fyne，只重写页面布局**：改动最小，但 335MB 的基线和字体缓存不会消失，且 Fyne 的表格/表单控件本身缺少想要的响应式能力；用户明确否掉了这条路。
- **Wails v3（Go + 系统 WebView2/WKWebView）**：能复用同一套 HTML/CSS，界面质量高，但每个平台仍要带 WebView 运行时，常驻内存预计多 100–200MB，还得引入前端构建流程。对一个 25MB 的常驻网络工具来说代价过高。
- **Gio**：纯 Go、内存比 Fyne 低，但仍是即时模式 GUI，复杂表单和表格要自己画，开发量和可访问性都不划算。
- **lxn/walk**：Windows 原生控件足够轻，但只支持 Windows，且无法复用现有跨平台结构。
- **把控制台做成可远程访问的 WebUI**：省掉托盘，但会暴露 Token 编辑入口；需要完整的认证、TLS、CSRF 体系，远超这个项目的范围。
- **只保留 `--daemon` + 手改 YAML**：内存最低，但配置 Token、做入站检测都要开终端，违背了「桌面小工具」的定位。

## Consequences

- 实测常驻内存从 335–340MB 降到约 25MB Working Set / 19MB Private（同一台 Windows 机器、同样 9 个 IPv6 地址、daemon 正常运行）。
- 界面第一次可以做到真正的响应式、深浅色、粘性表头、可访问表单和中文日志；代价是 UI 从「原生窗口」变成了「浏览器标签页」，用户需要本机有可用浏览器。
- 控制台端口被占用时自动退到随机端口，URL 打印到终端；`admin_port` 的修改要重启进程才生效，这和其他配置「保存即生效」不同。
- 令牌随进程重启而变，旧标签页会收到 401 并提示刷新——这是有意的，不引入持久会话。
- Linux 托盘依赖桌面提供 StatusNotifierItem/DBus host；无桌面环境的部署应继续用 `--daemon`。
- macOS 构建从此必须用 cgo，CI 的 darwin job 保留 `CGO_ENABLED=1`；Fyne 时代安装的那批 X11/GL 开发库已从 CI 删除。

## Verification

- `gofmt -l`（新增文件）、`go vet ./...`、`go test ./...` 全绿；新增控制台测试覆盖令牌、Host/Origin 守卫、索引令牌注入、配置 GET/PUT 往返、日志游标和方法限制；新增日志环形缓冲测试。
- 用真实进程 + 无头 Chrome 验证：五个页面均能渲染；`#/settings` 的表单能加载/校验/撤销；主题切换写入 `localStorage` 并即时改色；复制按钮在聚焦文档后返回「已复制」；「立即更新」完成一次真实 cycle，toast、状态徽标和日志同步刷新。
- 交叉编译 `GOOS=linux CGO_ENABLED=0` 与 `GOOS=windows CGO_ENABLED=0 -H=windowsgui` 成功；Windows 产物 7.7MB（strip 后）。
