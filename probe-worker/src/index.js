/**
 * v6-inbound-probe — Cloudflare 边缘的入站可达性探针。
 *
 * 用法：
 *   GET https://v6probe.254253.xyz/?host=<域名>&port=<端口>&timeout=5000
 *
 * 从 Cloudflare 边缘节点主动 TCP 连接指定域名的 IPv6 地址。
 * 连上了 = 公网真的能连进你的机器（入站可达）。
 *
 * 重要：Cloudflare Workers 的 connect() 只接受**域名**作为 hostname，
 * 不接受 IP 字面地址（IPv4 和 IPv6 字面都会被拒绝）。所以目标必须是一个
 * 解析到目标 IPv6 的域名——用它做一次临时 AAAA 记录即可。
 */

import { connect } from 'cloudflare:sockets';

const MAX_TIMEOUT_MS = 15000;
const DEFAULT_TIMEOUT_MS = 6000;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
};

function json(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), { status, headers: CORS });
}

/** 校验是否是合法域名（不接受 IP 字面） */
function validHostname(raw) {
  if (!raw) return null;
  const h = raw.trim().toLowerCase().replace(/\.$/, '');
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) return null; // IPv4 字面
  if (h.includes(':')) return null;                  // IPv6 字面
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(h)) return null;
  return h;
}

function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timeout after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export default {
  async fetch(request) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);
    const host = validHostname(url.searchParams.get('host'));
    const port = Number(url.searchParams.get('port') || '443');
    const timeoutMs = Math.min(
      Math.max(Number(url.searchParams.get('timeout')) || DEFAULT_TIMEOUT_MS, 100),
      MAX_TIMEOUT_MS,
    );

    if (!host) {
      return json({
        ok: false,
        error: 'host 必须是域名（不能是 IP 字面地址——Workers connect() 不支持 IP）',
        hint: '例：?host=target.254253.xyz&port=38080  （该域名需有 AAAA 记录指向你的 IPv6）',
      }, 400);
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535 || port === 25) {
      return json({ ok: false, error: 'port 必须是 1-65535 且不能是 25' }, 400);
    }

    const started = Date.now();
    let socket;
    try {
      socket = connect({ hostname: host, port });
      await withTimeout(socket.opened, timeoutMs);
      const latencyMs = Date.now() - started;
      const info = socket.remoteAddress ? { remoteAddress: socket.remoteAddress } : {};
      socket.close().catch(() => {});
      return json({
        ok: true,
        reachable: true,
        host,
        port,
        latencyMs,
        from: 'cloudflare-edge',
        ...info,
        note: '从 Cloudflare 边缘主动 TCP 连接成功 = 外网可入站',
      });
    } catch (err) {
      if (socket) socket.close().catch(() => {});
      return json({
        ok: true,
        reachable: false,
        host,
        port,
        latencyMs: Date.now() - started,
        from: 'cloudflare-edge',
        error: String(err && err.message ? err.message : err),
        note: '连接失败：检查 AAAA 记录、光猫/运营商 IPv6 入站、本机防火墙或服务是否监听',
      });
    }
  },
};
