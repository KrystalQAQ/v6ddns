// v6ddns local console — vanilla JS, no framework, no build step.
// All server data is rendered with textContent; untrusted strings never become
// markup. The console is served from 127.0.0.1 and every API call carries the
// per-process token embedded in the page.
(() => {
  "use strict";

  const TOKEN = document.querySelector('meta[name="v6ddns-token"]')?.content || "";
  const THEME_KEY = "v6ddns-theme";
  const POLL_MS = 4000;
  const PAGES = ["overview", "addresses", "neighbors", "ddns", "inbound", "settings"];
  const PAGE_TITLES = {
    overview: "总览",
    addresses: "IPv6 地址",
    neighbors: "局域网设备",
    ddns: "DDNS",
    inbound: "入站检测",
    settings: "配置",
  };
  const POLICY_LABELS = {
    "stable-auto": "稳定且可达",
    "any-reachable": "任意可达",
    manual: "手动指定",
  };
  const KIND_LABELS = {
    GUA: "公网 GUA",
    ULA: "本地 ULA",
    "link-local": "链路本地",
    loopback: "回环",
    multicast: "组播",
    unspecified: "未指定",
    other: "其他",
  };
  const NEIGH_STATE_LABELS = {
    REACHABLE: "可达",
    STALE: "陈旧",
    DELAY: "延迟",
    PROBE: "探测中",
    PERMANENT: "永久",
    NOARP: "不解析",
  };
  const SOURCE_LABELS = {
    interface: "网卡",
    mac: "MAC",
    "public-ipv4": "公网 IPv4",
  };
  const MESSAGES = {
    "no usable IPv6 address": "没有可用的 IPv6 地址",
    "IPv6 unchanged, skipped": "地址未变化，已跳过",
    "IPv4 unchanged, skipped": "IPv4 未变化，已跳过",
    "AAAA record updated": "AAAA 记录已更新",
    "AAAA record created": "AAAA 记录已创建",
    "A record updated": "A 记录已更新",
    "A record created": "A 记录已创建",
  };

  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const state = {
    page: "",
    status: null,
    config: null,
    record: null,
    neighbors: null,
    neighborsAt: 0,
    dirty: false,
    logCursor: 0,
    lastLogSeq: 0,
    pollBusy: false,
    authWarned: false,
  };

  // ---------------------------------------------------------------- API

  async function api(path, { method = "GET", body, timeout = 20000 } = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    try {
      const res = await fetch(path, {
        method,
        headers: {
          Accept: "application/json",
          "X-V6DDNS-Token": TOKEN,
          ...(body === undefined ? {} : { "Content-Type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        cache: "no-store",
        signal: ctrl.signal,
      });
      const text = await res.text();
      let data = null;
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          data = null;
        }
      }
      if (!res.ok) {
        const err = new Error(data?.error || `请求失败（HTTP ${res.status}）`);
        err.code = res.status;
        throw err;
      }
      return data;
    } catch (err) {
      if (err.name === "AbortError") throw new Error("请求超时，请稍后再试");
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  // ------------------------------------------------------------- format

  function relative(iso) {
    if (!iso) return "—";
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return "—";
    const diff = Date.now() - t;
    if (diff < 10000) return "刚刚";
    const s = Math.floor(diff / 1000);
    if (s < 60) return `${s} 秒前`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m} 分钟前`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h} 小时前`;
    const d = Math.floor(h / 24);
    if (d < 7) return `${d} 天前`;
    return dateTime(iso);
  }

  function dateTime(iso) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return "—";
    return new Intl.DateTimeFormat("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date(t));
  }

  function clock(iso) {
    const t = Date.parse(iso);
    if (Number.isNaN(t)) return "--:--:--";
    return new Intl.DateTimeFormat("zh-CN", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }).format(new Date(t));
  }

  function durationText(value) {
    const raw = String(value || "");
    const ms = durationMs(raw);
    if (Number.isNaN(ms)) return raw || "—";
    if (ms >= 3600000) return `${round1(ms / 3600000)} 小时`;
    if (ms >= 60000) return `${round1(ms / 60000)} 分钟`;
    if (ms >= 1000) return `${round1(ms / 1000)} 秒`;
    return `${Math.round(ms)} 毫秒`;
  }

  function round1(n) {
    return Number.isInteger(n) ? String(n) : n.toFixed(1);
  }

  function latencyText(ms) {
    if (!Number.isFinite(ms) || ms <= 0) return "—";
    return ms < 1 ? "<1 ms" : `${Math.round(ms)} ms`;
  }

  function explainMessage(msg) {
    if (!msg) return "";
    if (MESSAGES[msg]) return MESSAGES[msg];
    const unchanged = /^(\d+) records unchanged$/.exec(msg);
    if (unchanged) return `${unchanged[1]} 条记录均未变化`;
    const mixed = /^(\d+) records: (\d+) updated, (\d+) unchanged(?:, (\d+) failed)?$/.exec(msg);
    if (mixed) {
      const failed = mixed[4] ? `，${mixed[4]} 条失败` : "";
      return `${mixed[1]} 条记录：${mixed[2]} 条已更新，${mixed[3]} 条未变化${failed}`;
    }
    return msg;
  }

  function policyText(policy) {
    return POLICY_LABELS[policy] || policy || "—";
  }

  // ------------------------------------------------------------- render

  function setText(id, value) {
    const node = $(id);
    if (node) node.textContent = value == null || value === "" ? "—" : String(value);
  }

  function setPill(node, tone, text, title = "") {
    if (!node) return;
    node.className = "pill" + (tone ? ` ${tone}` : "");
    const dot = node.querySelector(".dot");
    if (dot) dot.className = "dot" + (tone === "ok" ? " ok" : tone === "err" ? " err" : tone === "warn" ? " warn" : "");
    const label = node.querySelector(".pill-text");
    if (label) label.textContent = text;
    node.title = title;
  }

  function badge(text, tone = "") {
    const span = document.createElement("span");
    span.className = "badge" + (tone ? ` ${tone}` : "");
    span.textContent = text;
    return span;
  }

  function setSide(tone, title, detail) {
    const dot = $("side-dot");
    if (dot) dot.className = "dot" + (tone ? ` ${tone}` : "");
    setText("side-state", title);
    setText("side-detail", detail);
  }

  function renderStatus(st) {
    if (!st) return;
    state.status = st;
    const ev = st.last_event || {};
    const published = st.published_ip || "";

    setText("side-version", st.version || "v6ddns");
    setText("hero-ip", published || "—");
    setText("hero-domain", st.domain || "未配置域名");
    setText("hero-interval", durationText(st.interval));
    setText("hero-policy", policyText(st.policy));
    setText("hero-time", ev.time ? relative(ev.time) : "—");
    if (ev.time) $("hero-time")?.setAttribute("title", dateTime(ev.time));

    let tone = "";
    let label = "等待首次更新";
    if (ev.running) {
      tone = "info";
      label = "正在更新…";
    } else if (ev.error) {
      tone = "err";
      label = "上次运行失败";
    } else if (ev.time && ev.updated) {
      tone = "ok";
      label = "已更新";
    } else if (ev.time) {
      tone = "ok";
      label = "已同步";
    }
    setPill($("hero-status"), tone, label);

    const message = $("hero-message");
    if (message) {
      if (ev.error) {
        message.textContent = ev.error;
      } else if (ev.message) {
        message.textContent = explainMessage(ev.message);
      } else {
        message.textContent = "后台会按配置的间隔自动检测并同步。";
      }
    }

    if (st.listener?.ok) {
      setSide("ok", "运行中", `${st.domain || "未配置域名"} · 每 ${durationText(st.interval)}`);
    } else if (ev.error) {
      setSide("err", "上次运行出错", ev.error);
    } else {
      setSide("warn", "监听未启动", st.listener?.error || "公网入站检测暂时不可用");
    }

    setText("stat-listen-value", st.listener?.ok ? st.listener.address : "未启动");
    setText("stat-listen-note", st.listener?.ok ? "用于公网入站检测" : st.listener?.error || "监听没有启动");
    setText("stat-record-value", published || "—");
    setText("stat-record-note", st.domain ? `${st.domain} · 可在 DDNS 页读取线上值` : "尚未配置域名");

    const aRecord = (st.records || []).find((r) => r.type === "A" || r.source === "public-ipv4");
    let ipv4Value = "等待首次更新";
    if (!st.ipv4_domain) ipv4Value = "未配置";
    else if (aRecord?.error) ipv4Value = "更新失败";
    else if (aRecord) ipv4Value = aRecord.new_ip || aRecord.old_ip || "—";
    setText("stat-ipv4-value", ipv4Value);
    setText("stat-ipv4-note", st.ipv4_domain ? `${st.ipv4_domain} · A 记录` : "在配置页填写 IPv4 域名后启用");
    const ipv4Note = $("stat-ipv4-note");
    if (ipv4Note) ipv4Note.title = aRecord?.error || "";

    const inbound = st.last_inbound;
    if (inbound) {
      setText("stat-inbound-value", inbound.reachable ? `可达 · ${latencyText(inbound.latency_ms)}` : "不可达");
      setText("stat-inbound-note", inbound.time ? `${inbound.target} · ${relative(inbound.time)}` : inbound.target || "最近一次检测");
    } else {
      setText("stat-inbound-value", "未检测");
      setText("stat-inbound-note", "从 Cloudflare 边缘发起连接");
    }

    renderAddresses(st.addresses || []);
    renderRecords(st.records || []);
    renderInbound(st);
    renderLocal(published);
  }

  function addCell(tr, label, child) {
    const td = document.createElement("td");
    td.dataset.label = label;
    if (typeof child === "string") td.textContent = child;
    else if (child) td.append(child);
    tr.append(td);
  }

  function codeCell(tr, text) {
    const th = document.createElement("th");
    th.scope = "row";
    const code = document.createElement("code");
    code.textContent = text || "—";
    th.append(code);
    tr.append(th);
  }

  function renderAddresses(list) {
    const body = $("addr-body");
    if (!body) return;
    const rows = list.map((addr) => {
      const tr = document.createElement("tr");
      codeCell(tr, addr.ip);

      addCell(tr, "网卡", addr.interface || "—");
      const kind = String(addr.kind || "other");
      addCell(tr, "类型", badge(KIND_LABELS[kind] || kind, kindClass(kind)));
      addCell(tr, "稳定", badge(addr.stable ? "长期" : "临时", addr.stable ? "" : "warn"));

      let reach;
      if (addr.reachable) {
        reach = badge("可达", "ok");
      } else if (addr.method === "not-gua") {
        reach = badge("不适用", "");
      } else if (addr.error) {
        reach = badge("不可达", "err");
        reach.title = addr.error;
      } else {
        reach = badge("未探测", "");
      }
      addCell(tr, "可达", reach);
      const latency = latencyText(addr.latency_ms);
      const latencyNode = document.createElement("span");
      latencyNode.textContent = latency;
      if (addr.method) latencyNode.title = addr.error ? `${addr.method} · ${addr.error}` : addr.method;
      addCell(tr, "延迟", latencyNode);
      return tr;
    });

    body.replaceChildren(...rows);
    const hasRows = list.length > 0;
    const wrapper = body.closest(".table-wrapper");
    if (wrapper) wrapper.hidden = !hasRows;
    const empty = $("addr-empty");
    if (empty) empty.hidden = hasRows;

    setText("sum-total", list.length);
    setText("sum-gua", list.filter((a) => a.kind === "GUA").length);
    setText("sum-reach", list.filter((a) => a.reachable).length);
  }

  function renderNeighbors(list) {
    const body = $("neigh-body");
    if (!body) return;
    const rows = list.map((n) => {
      const tr = document.createElement("tr");
      codeCell(tr, n.mac);
      addCell(tr, "地址", n.ip || "—");
      addCell(tr, "网卡", n.interface || "—");

      const state = String(n.state || "").toUpperCase();
      const tone = state === "REACHABLE" ? "ok" : ["STALE", "DELAY", "PROBE"].includes(state) ? "warn" : "";
      addCell(tr, "状态", badge(NEIGH_STATE_LABELS[state] || state || "—", tone));

      const kind = String(n.kind || "other");
      const types = document.createElement("span");
      types.className = "badge-group";
      if (n.gua) types.append(badge("公网 GUA", "gua"));
      else types.append(badge(KIND_LABELS[kind] || kind, kindClass(kind)));
      if (n.eui64) types.append(badge("EUI-64", ""));
      addCell(tr, "类型", types);

      const wake = document.createElement("button");
      wake.type = "button";
      wake.className = "btn wake-btn";
      wake.title = `唤醒 ${n.mac}`;
      wake.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-power"/></svg><span>唤醒</span>';
      wake.addEventListener("click", () => wakeDevice(n.mac, wake));
      addCell(tr, "操作", wake);
      return tr;
    });

    body.replaceChildren(...rows);
    const hasRows = list.length > 0;
    const wrapper = body.closest(".table-wrapper");
    if (wrapper) wrapper.hidden = !hasRows;
    const empty = $("neigh-empty");
    if (empty) empty.hidden = hasRows;

    setText("neigh-total", list.length);
    setText("neigh-gua", list.filter((n) => n.gua).length);
    renderWakeOptions(list);
  }

  // ------------------------------------------------------------- wake

  const MAC_PATTERN = /^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$/i;

  function setWakeResult(text, tone = "") {
    const node = $("wake-result");
    if (!node) return;
    node.textContent = text;
    if (tone) node.dataset.tone = tone;
    else delete node.dataset.tone;
  }

  function renderWakeOptions(list) {
    const dl = $("wake-macs");
    if (!dl) return;
    const seen = new Set();
    const options = [];
    for (const n of list) {
      const mac = String(n.mac || "").toLowerCase();
      if (!mac || seen.has(mac)) continue;
      seen.add(mac);
      const option = document.createElement("option");
      option.value = mac;
      const hint = [n.ip, n.interface].filter(Boolean).join(" · ");
      if (hint) option.label = hint;
      options.push(option);
    }
    dl.replaceChildren(...options);
  }

  // Waking a machine is the one action that needs a MAC rather than an
  // address: a sleeping device has no neighbour entry left to look up.
  async function wakeDevice(mac, btn) {
    const value = String(mac || "").trim();
    if (!MAC_PATTERN.test(value)) {
      setWakeResult("MAC 格式不对，示例：aa:bb:cc:dd:ee:ff", "err");
      $("wake-mac")?.focus();
      return;
    }
    setBusy(btn, true, "发送中…");
    setWakeResult(`正在向 ${value} 广播魔包…`);
    try {
      const data = await api("/api/wake", { method: "POST", body: { mac: value }, timeout: 15000 });
      const result = data?.result || {};
      const targets = Array.isArray(result.targets) ? result.targets : [];
      const failed = Array.isArray(result.errors) ? result.errors : [];
      const tone = failed.length ? "warn" : "ok";
      setWakeResult(
        `魔包已发往 ${result.mac || value}：${targets.length} 个广播目标` +
          (failed.length ? `，${failed.length} 个失败` : "") +
          "。设备一般 5–30 秒内开始开机。",
        tone,
      );
      toast(`唤醒 ${result.mac || value}：已发送`, tone);
      const input = $("wake-mac");
      if (input) input.value = "";
    } catch (err) {
      const message = err?.message || "唤醒失败";
      setWakeResult(message, "err");
      toast(message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  function wakeFromInput(btn) {
    const input = $("wake-mac");
    wakeDevice(input ? input.value : "", btn);
  }

  function renderRecords(records) {
    const card = $("records-card");
    const body = $("records-body");
    if (!card || !body) return;
    const list = Array.isArray(records) ? records : [];
    card.hidden = list.length === 0;
    const rows = list.map((r) => {
      const tr = document.createElement("tr");
      const type = r.type || (r.source === "public-ipv4" ? "A" : "AAAA");
      codeCell(tr, r.domain);
      addCell(tr, "类型", badge(type, type === "A" ? "type-a" : "type-aaaa"));
      addCell(tr, "来源", SOURCE_LABELS[r.source] || r.source || "—");
      addCell(tr, "地址", r.new_ip || r.old_ip || "—");

      let state;
      if (r.error) {
        state = badge("失败", "err");
        state.title = r.error;
      } else if (r.updated) {
        state = badge("已更新", "ok");
      } else {
        state = badge("未变化", "");
      }
      addCell(tr, "状态", state);
      const note = r.error || explainMessage(r.message) || "—";
      const noteNode = document.createElement("span");
      noteNode.textContent = note;
      if (r.error) noteNode.title = r.error;
      addCell(tr, "说明", noteNode);
      return tr;
    });
    body.replaceChildren(...rows);
  }

  function kindClass(kind) {
    switch (kind) {
      case "GUA":
        return "gua";
      case "ULA":
        return "ula";
      case "link-local":
        return "link-local";
      case "loopback":
        return "loopback";
      default:
        return "other";
    }
  }

  function renderInbound(st) {
    setText("in-listen", st.listener?.ok ? st.listener.address : "未启动");
    setText("in-domain", st.domain || "未配置");
    setText("in-port", st.inbound_port || st.listen_port || "—");
    const pill = $("inbound-pill");
    const detail = $("inbound-detail");
    const last = st.last_inbound;
    if (!last) {
      setPill(pill, "", "尚未检测");
      if (detail) detail.textContent = "点击右上角「从公网检测」开始。";
      return;
    }
    if (last.reachable) {
      setPill(pill, "ok", `可达 · ${latencyText(last.latency_ms)}`);
    } else {
      setPill(pill, "err", "不可达", last.error || "");
    }
    if (detail) {
      const when = last.time ? dateTime(last.time) : "—";
      const extra = last.error ? ` · ${last.error}` : "";
      detail.textContent = `${last.target || "—"} · ${when}${extra}`;
    }
  }

  function renderLocal(published) {
    const rec = state.record?.record;
    setText("local-ip", published || "");
    const match = $("local-match");
    if (match) {
      if (!published) {
        match.textContent = "等待首次更新";
      } else if (!rec) {
        match.textContent = state.record?.error ? "线上记录读取失败" : "—";
      } else if (rec.content === published) {
        match.replaceChildren(badge("已匹配", "ok"));
      } else {
        match.replaceChildren(badge("与线上不一致", "warn"));
      }
    }
    const ev = state.status?.last_event;
    const result = $("local-result");
    if (result) {
      if (ev?.error) result.textContent = ev.error;
      else if (ev?.message) {
        result.textContent = ev.time
          ? `${explainMessage(ev.message)} · ${relative(ev.time)}`
          : explainMessage(ev.message);
      } else result.textContent = "—";
    }
  }

  function renderRecord() {
    const rec = state.record?.record || null;
    const err = state.record?.error || "";
    const pill = $("remote-state");
    setText("remote-domain", rec?.name || state.status?.domain || "—");
    setText("remote-content", rec?.content || "—");
    setText("remote-ttl", rec ? (rec.ttl === 1 ? "自动 (1)" : `${rec.ttl} 秒`) : "—");
    setText("remote-proxied", rec ? (rec.proxied ? "橙云（代理）" : "灰云（DNS only）") : "—");
    if (rec) {
      setPill(pill, "ok", "已读取");
    } else if (err) {
      setPill(pill, "err", "读取失败", err);
    } else {
      setPill(pill, "", "未读取");
    }
    renderLocal(state.status?.published_ip || "");
  }

  // -------------------------------------------------------------- theme

  function setTheme(mode, persist = true) {
    if (!["system", "light", "dark"].includes(mode)) mode = "system";
    const meta = document.querySelector('meta[name="color-scheme"]');
    if (meta) meta.content = mode === "light" ? "light" : mode === "dark" ? "dark" : "light dark";
    document.documentElement.dataset.theme = mode;
    for (const btn of $$("[data-theme]")) {
      btn.setAttribute("aria-pressed", String(btn.dataset.theme === mode));
    }
    if (persist) {
      try {
        localStorage.setItem(THEME_KEY, mode);
      } catch {
        /* private mode */
      }
    }
  }

  // ------------------------------------------------------------- toasts

  function toast(message, tone = "ok") {
    const box = $("toasts");
    if (!box) return;
    const el = document.createElement("div");
    el.className = `toast ${tone}`;
    el.textContent = message;
    el.tabIndex = 0;
    el.addEventListener("click", () => el.remove());
    el.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        el.remove();
      }
    });
    box.append(el);
    while (box.childElementCount > 3) box.firstElementChild.remove();
    setTimeout(() => el.remove(), 4500);
  }

  // ------------------------------------------------------------- copy

  async function copyText(text) {
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        return true;
      } catch {
        /* fall through to the selection-based copy */
      }
    }
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.top = "-1000px";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    let ok = false;
    try {
      ok = document.execCommand("copy");
    } catch {
      ok = false;
    }
    area.remove();
    return ok;
  }

  async function copyWithFeedback(btn) {
    const target = $(btn.getAttribute("commandfor") || "");
    const text = target?.textContent?.trim() || "";
    const tip = btn.parentElement?.querySelector(".tip");
    const done = (ok, label) => {
      delete btn.dataset.copied;
      delete btn.dataset.failed;
      if (ok) btn.dataset.copied = "";
      else btn.dataset.failed = "";
      if (tip) tip.textContent = label;
      clearTimeout(btn._tipTimer);
      btn._tipTimer = setTimeout(() => {
        delete btn.dataset.copied;
        delete btn.dataset.failed;
        if (tip) tip.textContent = "";
      }, 1600);
    };
    if (!text || text === "—") {
      done(false, "暂无内容");
      return;
    }
    done(await copyText(text), "已复制");
  }

  // ------------------------------------------------------------- logs

  async function pollLogs() {
    try {
      const data = await api(`/api/logs?after=${state.logCursor}`, { timeout: 8000 });
      if (Array.isArray(data?.lines) && data.lines.length) appendLogs(data.lines);
      if (typeof data?.next === "number") state.logCursor = data.next;
      const list = $("log-list");
      if (list && list.childElementCount === 0) {
        const empty = document.createElement("div");
        empty.className = "log-empty";
        empty.textContent = "暂无日志。";
        list.append(empty);
      }
    } catch {
      /* transient; the next tick retries */
    }
  }

  function appendLogs(lines) {
    const list = $("log-list");
    if (!list) return;
    const nearBottom = list.scrollHeight - list.scrollTop - list.clientHeight < 48;
    const frag = document.createDocumentFragment();
    let added = 0;

    for (const line of lines) {
      if (!line || typeof line.seq !== "number" || line.seq <= state.lastLogSeq) continue;
      state.lastLogSeq = line.seq;
      const row = document.createElement("div");
      row.className = "log-line";

      const time = document.createElement("span");
      time.className = "log-time";
      time.textContent = clock(line.time);
      time.title = dateTime(line.time);

      const levelName = String(line.level || "INFO").toUpperCase();
      const level = document.createElement("span");
      const lc = String(line.level || "info").toLowerCase();
      level.className = `log-level ${["info", "warn", "error", "debug"].includes(lc) ? lc : "info"}`;
      level.textContent = levelName;

      const text = document.createElement("span");
      text.className = "log-text";
      text.textContent = line.text || "";

      row.append(time, level, text);
      frag.append(row);
      added++;
    }
    if (!added) return;

    const empty = list.querySelector(".log-empty");
    if (empty) empty.remove();
    list.append(frag);
    while (list.childElementCount > 300) list.firstElementChild.remove();
    if (nearBottom) list.scrollTop = list.scrollHeight;
  }

  // ------------------------------------------------------------- loaders

  async function refreshStatus({ quiet = false } = {}) {
    try {
      const st = await api("/api/status", { timeout: 8000 });
      renderStatus(st);
      return st;
    } catch (err) {
      if (err.code === 401) {
        if (!state.authWarned) {
          state.authWarned = true;
          toast(err.message, "err");
        }
        setSide("err", "令牌已失效", "请刷新页面重新载入控制台");
      } else {
        setSide("err", "服务无响应", err.message);
        if (!quiet) toast(err.message, "err");
      }
      return null;
    }
  }

  async function loadRecord({ quiet = false } = {}) {
    const btn = $("btn-record-refresh");
    setBusy(btn, true, "读取中…");
    try {
      const data = await api("/api/record", { timeout: 25000 });
      state.record = { record: data.record, error: "", at: Date.now() };
      if (!quiet) toast("已读取 Cloudflare 记录", "ok");
    } catch (err) {
      state.record = { record: null, error: err.message, at: Date.now() };
      if (!quiet) toast(err.message, "err");
    } finally {
      setBusy(btn, false);
      renderRecord();
    }
  }

  async function ensureRecord(force = false) {
    const fresh = state.record && Date.now() - state.record.at < 15000;
    if (!force && fresh) {
      renderRecord();
      return;
    }
    await loadRecord({ quiet: !force });
  }

  async function loadNeighbors({ quiet = false } = {}) {
    const btn = $("btn-neighbors-refresh");
    setBusy(btn, true, "读取中…");
    setBusy($("btn-neighbors-empty"), true, "读取中…");
    try {
      const data = await api("/api/neighbors", { timeout: 20000 });
      state.neighbors = Array.isArray(data?.neighbors) ? data.neighbors : [];
      state.neighborsAt = Date.now();
      renderNeighbors(state.neighbors);
      if (!quiet) toast(`读到 ${state.neighbors.length} 台 IPv6 设备`, "ok");
    } catch (err) {
      state.neighborsAt = 0;
      renderNeighbors(state.neighbors || []);
      if (!quiet) toast(err.message, "err");
    } finally {
      setBusy(btn, false);
      setBusy($("btn-neighbors-empty"), false);
    }
  }

  async function ensureNeighbors(force = false) {
    const fresh = state.neighbors && Date.now() - state.neighborsAt < 15000;
    if (!force && fresh) {
      renderNeighbors(state.neighbors);
      return;
    }
    await loadNeighbors({ quiet: !force });
  }

  async function loadConfig() {
    try {
      const cfg = await api("/api/config", { timeout: 10000 });
      fillConfig(cfg);
      setSaveStatus("", "");
    } catch (err) {
      setSaveStatus(err.message, "err");
      toast(err.message, "err");
    }
  }

  function ensureConfig() {
    if (!state.config) loadConfig();
  }

  // ------------------------------------------------------------- actions

  async function runUpdate(btn) {
    setBusy(btn, true, "更新中…");
    try {
      const data = await api("/api/update", { method: "POST", timeout: 130000 });
      if (data.status) renderStatus(data.status);
      const ev = data.event || {};
      if (ev.error) {
        toast(`更新失败：${ev.error}`, "err");
      } else if (ev.updated) {
        toast(`AAAA 记录已更新为 ${ev.new_ip}`, "ok");
      } else {
        toast(explainMessage(ev.message) || "地址未变化，无需更新", "ok");
      }
      if (state.page === "ddns") state.record = null;
      await refreshStatus({ quiet: true });
    } catch (err) {
      toast(err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  async function runDetect(btn) {
    setBusy(btn, true, "检测中…");
    setBusy($("btn-detect-empty"), true, "检测中…");
    try {
      const data = await api("/api/detect", { method: "POST", timeout: 110000 });
      if (data.status) renderStatus(data.status);
      else renderAddresses(data.addresses || []);
      toast(`检测完成，共 ${data.addresses?.length || 0} 个 IPv6 地址`, "ok");
    } catch (err) {
      toast(err.message, "err");
    } finally {
      setBusy(btn, false);
      setBusy($("btn-detect-empty"), false);
    }
  }

  async function runInbound(btn) {
    setBusy(btn, true, "检测中…");
    try {
      const data = await api("/api/inbound-check", { method: "POST", timeout: 165000 });
      if (data.status) renderStatus(data.status);
      const res = data.result || {};
      if (res.error) {
        toast(res.error, "err");
      } else if (res.reachable) {
        toast(`公网入站可达，延迟 ${latencyText(res.latency_ms)}`, "ok");
      } else {
        toast("公网无法连入本机，请检查防火墙与 IPv6 入站策略", "err");
      }
      if (state.page === "ddns") state.record = null;
    } catch (err) {
      toast(err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  function setBusy(btn, busy, label = "") {
    if (!btn) return;
    const span = btn.querySelector("span");
    if (busy) {
      if (span) {
        btn.dataset.label ||= span.textContent;
        span.textContent = label || span.textContent;
      }
      btn.disabled = true;
      btn.classList.add("busy");
    } else {
      if (span && btn.dataset.label) {
        span.textContent = btn.dataset.label;
        delete btn.dataset.label;
      }
      btn.disabled = false;
      btn.classList.remove("busy");
    }
  }

  // ------------------------------------------------------------- form

  function value(id) {
    return ($(id)?.value || "").trim();
  }

  function checked(id) {
    return Boolean($(id)?.checked);
  }

  function intValue(id) {
    const raw = value(id);
    return /^\d+$/.test(raw) ? Number(raw) : 0;
  }

  function fillConfig(cfg) {
    state.config = cfg;
    state.dirty = false;
    const set = (id, v) => {
      const node = $(id);
      if (node) node.value = v == null ? "" : String(v);
    };
    set("cfg-token", cfg.api_token);
    set("cfg-zone", cfg.zone_id);
    set("cfg-domain", cfg.domain);
    set("cfg-ipv4-domain", cfg.ipv4_domain);
    set("cfg-ttl", cfg.ttl);
    set("cfg-iface", cfg.interface_name);
    set("cfg-policy", cfg.policy || "stable-auto");
    set("cfg-address", cfg.address);
    set("cfg-probes", (cfg.probe_targets || []).join(", "));
    set("cfg-probe-timeout", cfg.probe_timeout);
    set("cfg-interval", cfg.interval);
    set("cfg-listen-port", cfg.listen_port);
    set("cfg-admin-port", cfg.admin_port);
    set("cfg-worker", cfg.inbound_worker);
    set("cfg-inbound-port", cfg.inbound_port || "");
    set("cfg-probe-base", cfg.probe_base);
    if ($("cfg-proxied")) $("cfg-proxied").checked = Boolean(cfg.proxied);
    if ($("cfg-autostart")) $("cfg-autostart").checked = Boolean(cfg.autostart);
    if ($("cfg-require-inbound")) $("cfg-require-inbound").checked = Boolean(cfg.require_inbound);
    setText("config-path", cfg.config_path || "—");
    clearErrors();
    setSaveStatus("", "");
  }

  function formPayload() {
    return {
      api_token: value("cfg-token"),
      zone_id: value("cfg-zone"),
      domain: value("cfg-domain"),
      ipv4_domain: value("cfg-ipv4-domain"),
      ttl: intValue("cfg-ttl"),
      proxied: checked("cfg-proxied"),
      interface_name: value("cfg-iface"),
      interval: value("cfg-interval"),
      policy: value("cfg-policy"),
      address: value("cfg-address"),
      probe_targets: value("cfg-probes")
        .split(/[,\n]/)
        .map((s) => s.trim())
        .filter(Boolean),
      probe_timeout: value("cfg-probe-timeout"),
      listen_port: intValue("cfg-listen-port"),
      admin_port: intValue("cfg-admin-port"),
      inbound_worker: value("cfg-worker"),
      require_inbound: checked("cfg-require-inbound"),
      inbound_port: intValue("cfg-inbound-port"),
      probe_base: value("cfg-probe-base"),
      autostart: checked("cfg-autostart"),
    };
  }

  function durationMs(raw) {
    const s = raw.trim();
    if (!s) return NaN;
    const re = /(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)/g;
    const scale = { ns: 1e-6, us: 1e-3, "µs": 1e-3, ms: 1, s: 1000, m: 60000, h: 3600000 };
    let total = 0;
    let consumed = 0;
    let m;
    while ((m = re.exec(s))) {
      consumed += m[0].length;
      total += Number(m[1]) * scale[m[2]];
    }
    if (consumed !== s.length || total <= 0) return NaN;
    return total;
  }

  function portOK(raw, min) {
    if (!/^\d+$/.test(raw)) return false;
    const n = Number(raw);
    return n >= min && n <= 65535;
  }

  function ttlOK(raw) {
    if (!/^\d+$/.test(raw)) return false;
    const n = Number(raw);
    return n >= 1 && n <= 2147483647;
  }

  const DOMAIN_RE = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;

  const RULES = [
    { id: "cfg-token", err: "err-token", test: (v) => (v ? "" : "请填写 API Token") },
    { id: "cfg-zone", err: "err-zone", test: (v) => (v ? "" : "请填写 Zone ID") },
    {
      id: "cfg-domain",
      err: "err-domain",
      test: (v) =>
        !v
          ? "请填写域名"
          : DOMAIN_RE.test(v)
            ? ""
            : "域名格式不正确，例如 host.example.com",
    },
    {
      id: "cfg-ipv4-domain",
      err: "err-ipv4-domain",
      test: (v) => (!v || DOMAIN_RE.test(v) ? "" : "域名格式不正确，例如 v4.example.com"),
    },
    {
      id: "cfg-ttl",
      err: "err-ttl",
      test: (v) => (ttlOK(v) ? "" : "TTL 必须是 1-2147483647 的整数"),
    },
    {
      id: "cfg-interval",
      err: "err-interval",
      test: (v) => (Number.isNaN(durationMs(v)) ? "请填写合法间隔，例如 30s、5m、1h" : ""),
    },
    {
      id: "cfg-probe-timeout",
      err: "err-probe-timeout",
      test: (v) => (!v || !Number.isNaN(durationMs(v)) ? "" : "请填写合法时长，例如 5s"),
    },
    {
      id: "cfg-listen-port",
      err: "err-listen",
      test: (v) => (portOK(v, 1) ? "" : "端口必须是 1-65535"),
    },
    {
      id: "cfg-admin-port",
      err: "err-admin",
      test: (v) => (portOK(v, 1) ? "" : "端口必须是 1-65535"),
    },
    {
      id: "cfg-inbound-port",
      err: "err-inbound-port",
      test: (v) => (!v || portOK(v, 0) ? "" : "端口必须是 0-65535"),
    },
  ];

  function markField(rule, message) {
    const input = $(rule.id);
    if (!input) return;
    const field = input.closest(".field");
    const err = $(rule.err);
    if (message) {
      input.setAttribute("aria-invalid", "true");
      field?.classList.add("invalid");
      if (err) err.textContent = message;
    } else {
      input.removeAttribute("aria-invalid");
      field?.classList.remove("invalid");
      if (err) err.textContent = "";
    }
  }

  function validateField(rule) {
    const message = rule.test(value(rule.id));
    markField(rule, message);
    return !message;
  }

  function validateForm() {
    let ok = true;
    let firstBad = null;
    for (const rule of RULES) {
      if (!validateField(rule)) {
        ok = false;
        firstBad ||= $(rule.id);
      }
    }
    const listen = intValue("cfg-listen-port");
    const admin = intValue("cfg-admin-port");
    if (ok && listen === admin) {
      markField(RULES.find((r) => r.id === "cfg-admin-port"), "控制台端口不能与监听端口相同");
      ok = false;
      firstBad ||= $("cfg-admin-port");
    }
    if (!ok) {
      firstBad?.focus();
      setSaveStatus("请先修正表单里的问题", "err");
      toast("请先修正表单里的问题", "err");
    }
    return ok;
  }

  function clearErrors() {
    for (const rule of RULES) markField(rule, "");
  }

  function setSaveStatus(text, tone) {
    const node = $("save-status");
    if (!node) return;
    node.textContent = text;
    node.className = "save-status" + (tone ? ` ${tone}` : "");
  }

  function markDirty() {
    if (!state.config) return;
    state.dirty = true;
    setSaveStatus("有未保存的修改", "warn");
  }

  async function saveConfig(event) {
    event.preventDefault();
    if (!validateForm()) return;
    const btn = $("btn-config-save");
    const before = state.config;
    setBusy(btn, true, "保存中…");
    try {
      const cfg = await api("/api/config", {
        method: "PUT",
        body: formPayload(),
        timeout: 30000,
      });
      const adminChanged = before && cfg.admin_port !== before.admin_port;
      fillConfig(cfg);
      setSaveStatus("已保存并生效", "ok");
      toast("配置已保存并生效", "ok");
      if (adminChanged) {
        setSaveStatus(`控制台端口已改为 ${cfg.admin_port}，重启后生效`, "warn");
        toast(`控制台端口已改为 ${cfg.admin_port}，重启 v6ddns 后生效`, "ok");
      }
      await refreshStatus({ quiet: true });
    } catch (err) {
      setSaveStatus(err.message, "err");
      toast(err.message, "err");
    } finally {
      setBusy(btn, false);
    }
  }

  // ------------------------------------------------------------- router

  function pageFromHash() {
    const name = location.hash.replace(/^#\/?/, "");
    return PAGES.includes(name) ? name : "overview";
  }

  function navigate({ focus = false } = {}) {
    const page = pageFromHash();
    const changed = page !== state.page;
    state.page = page;
    for (const section of $$("[data-page]")) {
      section.hidden = section.dataset.page !== page;
    }
    for (const link of $$("[data-nav]")) {
      if (link.dataset.nav === page) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
    document.title = `${PAGE_TITLES[page]} · v6ddns`;
    if (changed) window.scrollTo(0, 0);

    if (page === "neighbors") ensureNeighbors();
    if (page === "ddns") ensureRecord();
    if (page === "settings") ensureConfig();
    if (page === "overview" && state.status) pollLogs();
    if (focus && changed) $("main")?.focus({ preventScroll: true });
  }

  // ------------------------------------------------------------- wiring

  function bind() {
    window.addEventListener("hashchange", () => navigate({ focus: true }));
    window.addEventListener("beforeunload", (e) => {
      if (state.dirty) {
        e.preventDefault();
        e.returnValue = "";
      }
    });
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) poll();
    });

    for (const btn of $$("[data-theme]")) {
      btn.addEventListener("click", () => setTheme(btn.dataset.theme));
    }

    $("btn-overview-refresh")?.addEventListener("click", async () => {
      await refreshStatus();
      await pollLogs();
    });
    $("btn-overview-update")?.addEventListener("click", (e) => runUpdate(e.currentTarget));
    $("btn-ddns-update")?.addEventListener("click", (e) => runUpdate(e.currentTarget));
    $("btn-detect")?.addEventListener("click", (e) => runDetect(e.currentTarget));
    $("btn-detect-empty")?.addEventListener("click", (e) => runDetect($("btn-detect")));
    $("btn-neighbors-refresh")?.addEventListener("click", () => ensureNeighbors(true));
    $("btn-neighbors-empty")?.addEventListener("click", () => ensureNeighbors(true));
  $("btn-wake")?.addEventListener("click", (e) => wakeFromInput(e.currentTarget));
  $("wake-mac")?.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    e.preventDefault();
    wakeFromInput($("btn-wake"));
  });
    $("btn-record-refresh")?.addEventListener("click", () => loadRecord());
    $("btn-inbound")?.addEventListener("click", (e) => runInbound(e.currentTarget));

    $("btn-reveal-token")?.addEventListener("click", (e) => {
      const btn = e.currentTarget;
      const input = $("cfg-token");
      if (!input) return;
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      btn.setAttribute("aria-pressed", String(reveal));
      btn.setAttribute("aria-label", reveal ? "隐藏 Token" : "显示 Token");
      btn.querySelector("use")?.setAttribute("href", reveal ? "#i-eye-off" : "#i-eye");
    });

    const form = $("config-form");
    form?.addEventListener("submit", saveConfig);
    form?.addEventListener("input", (e) => {
      markDirty();
      const rule = RULES.find((r) => r.id === e.target.id);
      if (rule && e.target.getAttribute("aria-invalid") === "true") {
        markField(rule, rule.test(value(rule.id)));
      }
    });
    form?.addEventListener("change", markDirty);
    form?.addEventListener(
      "blur",
      (e) => {
        const rule = RULES.find((r) => r.id === e.target.id);
        if (rule) validateField(rule);
      },
      true,
    );
    $("btn-config-reset")?.addEventListener("click", () => {
      if (!state.config) return;
      fillConfig(state.config);
      toast("已撤销未保存的修改", "ok");
    });

    // `command`/`commandfor` describe the intent declaratively, but Chromium
    // does not dispatch command events for custom (--) commands yet, so the
    // click handler is the one that actually performs the copy.
    document.addEventListener("click", (event) => {
      const btn = event.target?.closest?.(".copy-button");
      if (btn) copyWithFeedback(btn);
    });
  }

  async function poll() {
    if (state.pollBusy) return;
    state.pollBusy = true;
    try {
      await refreshStatus({ quiet: true });
      if (state.page === "overview") await pollLogs();
    } finally {
      state.pollBusy = false;
    }
  }

  function init() {
    setTheme(document.documentElement.dataset.theme || "system", false);
    if (!location.hash) history.replaceState(null, "", "#/overview");
    bind();
    navigate();
    refreshStatus().then(() => {
      if (state.page === "overview") pollLogs();
      if (state.page === "ddns") ensureRecord();
      if (state.page === "settings") ensureConfig();
    });
    setInterval(() => {
      if (!document.hidden) poll();
    }, POLL_MS);
  }

  init();
})();
