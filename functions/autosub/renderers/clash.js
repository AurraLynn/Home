/*
  - 输入支持：
      Parser.js 标准化后的 Node 数组（Node[]）

  - 当前渲染支持协议：
      • Shadowsocks    → type: "ss"
      • Trojan         → type: "trojan"
      • Hysteria2 / hy2 → type: "hysteria2" / "hy2"

  - 输出：
      Clash / Mihomo 通用 YAML（块状写法）
      带一个通用策略组：🐹Lyn · Node

  - 典型调用方式：
      /autosub?id=你的id&client=clash

  - 主要适配的客户端（是否真正支持某种协议由客户端决定）：
      Clash Meta / Mihomo / Clash Verge / Clash for Windows /
      FIClash / 溜溜 / NekoBox / FlyClash 等
*/

function pickString(v, fallback = "") {
  if (v === null || v === undefined) return fallback;
  const s = String(v).trim();
  return s || fallback;
}

function pickNumber(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/** 缩进 + 一行文本 */
function pushLine(lines, indentLevel, text) {
  const indent = "  ".repeat(indentLevel);
  lines.push(indent + text);
}

/** Node -> 内部 proxy 对象（_type 区分协议） */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();
  const server = pickString(node.server);
  const port = pickNumber(node.port);
  const nameBase =
    pickString(node.name) || (server && port ? `${server}:${port}` : "");
  const name = nameBase || "Unnamed";

  if (!server || !port) return null;

  // ---------- Shadowsocks ----------
  if (type === "ss") {
    const cipher = pickString(node.cipher || node.method);
    const password = pickString(node.password);

    if (!cipher || !password) return null;

    const proxy = {
      _type: "ss",
      name,
      server,
      port,
      cipher,
      password,
    };

    // 插件：obfs / simple-obfs / obfs-local → 统一渲染成 obfs
    if (node.plugin) {
      let pluginName = String(node.plugin).trim().toLowerCase();
      if (
        pluginName === "obfs-local" ||
        pluginName === "simple-obfs" ||
        pluginName === "simple-obfs-local"
      ) {
        proxy.plugin = "obfs"; // Clash 认识的是 obfs
      } else {
        proxy.plugin = node.plugin;
      }
    }

    if (node.pluginOpts && typeof node.pluginOpts === "object") {
      const src = node.pluginOpts;
      const opts = {};

      if (src.mode) opts.mode = src.mode; // http / tls
      if (src.host) opts.host = src.host;
      if (src.uri) opts.uri = src.uri;

      // 其它不常用字段照传
      for (const [k, v] of Object.entries(src)) {
        if (["mode", "host", "uri", "raw"].includes(k)) continue;
        if (v === undefined || v === null || v === "") continue;
        opts[k] = v;
      }

      if (Object.keys(opts).length > 0) {
        proxy.pluginOpts = opts;
      }
    }

    return proxy;
  }

  // ---------- Trojan（极简版） ----------
  if (type === "trojan") {
    const password = pickString(node.password);
    if (!password) return null;

    const proxy = {
      _type: "trojan",
      name,
      server,
      port,
      password,
    };

    const sni = pickString(node.sni || node.host);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy.skipCertVerify = node.skipCertVerify;
    }

    // 不输出 network / ws-opts / headers，避免兼容性问题
    return proxy;
  }

  // ---------- Hysteria2 / hy2 ----------
  if (type === "hysteria2" || type === "hy2") {
    // 收敛到 password 字段；auth 只用于输出兼容
    const pwd = pickString(node.password || node.auth);
    if (!pwd) return null;

    const proxy = {
      _type: "hysteria2",
      name,
      server,
      port,
      password: pwd,
    };

    const sni = pickString(node.sni || node.peer || node.serverName);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy.skipCertVerify = node.skipCertVerify;
    }

    const ports = pickString(node.ports || node.portRange);
    if (ports) proxy.ports = ports;

    if (typeof node.udp === "boolean") proxy.udp = node.udp;
    if (typeof node.fastOpen === "boolean") {
      proxy.fastOpen = node.fastOpen;
    }

    const obfs = pickString(node.obfs);
    if (obfs) proxy.obfs = obfs;

    return proxy;
  }

  // 其它协议暂不渲染进 Clash
  return null;
}

/** 输出单个 proxy 的块状 YAML */
function dumpProxyBlock(lines, proxy) {
  // 通用字段
  pushLine(
    lines,
    1,
    `- name: "${String(proxy.name).replace(/"/g, '\\"')}"`
  );
  pushLine(lines, 2, `type: ${proxy._type}`);
  pushLine(lines, 2, `server: ${proxy.server}`);
  pushLine(lines, 2, `port: ${proxy.port}`);

  // ---------- SS ----------
  if (proxy._type === "ss") {
    pushLine(lines, 2, `cipher: ${proxy.cipher}`);
    pushLine(lines, 2, `password: ${proxy.password}`);

    if (proxy.plugin) pushLine(lines, 2, `plugin: ${proxy.plugin}`);

    if (proxy.pluginOpts) {
      pushLine(lines, 2, `plugin-opts:`);
      if (proxy.pluginOpts.mode)
        pushLine(lines, 3, `mode: ${proxy.pluginOpts.mode}`);
      if (proxy.pluginOpts.host)
        pushLine(lines, 3, `host: ${proxy.pluginOpts.host}`);
      if (proxy.pluginOpts.uri)
        pushLine(lines, 3, `uri: ${proxy.pluginOpts.uri}`);
    }

    return;
  }

  // ---------- Trojan ----------
  if (proxy._type === "trojan") {
    pushLine(lines, 2, `password: ${proxy.password}`);
    if (proxy.sni) pushLine(lines, 2, `sni: ${proxy.sni}`);
    if (typeof proxy.skipCertVerify === "boolean") {
      pushLine(
        lines,
        2,
        `skip-cert-verify: ${proxy.skipCertVerify ? "true" : "false"}`
      );
    }
    return;
  }

  // ---------- Hysteria2 ----------
  if (proxy._type === "hysteria2") {
    // 同时输出 password + auth，客户端按自己支持的字段选
    pushLine(lines, 2, `password: ${proxy.password}`);
    pushLine(lines, 2, `auth: ${proxy.password}`);

    if (proxy.sni) pushLine(lines, 2, `sni: ${proxy.sni}`);
    if (typeof proxy.skipCertVerify === "boolean") {
      pushLine(
        lines,
        2,
        `skip-cert-verify: ${proxy.skipCertVerify ? "true" : "false"}`
      );
    }
    if (proxy.ports) pushLine(lines, 2, `ports: "${proxy.ports}"`);
    if (typeof proxy.udp === "boolean")
      pushLine(lines, 2, `udp: ${proxy.udp ? "true" : "false"}`);
    if (typeof proxy.fastOpen === "boolean") {
      pushLine(
        lines,
        2,
        `fast-open: ${proxy.fastOpen ? "true" : "false"}`
      );
    }
    if (proxy.obfs) pushLine(lines, 2, `obfs: ${proxy.obfs}`);
  }
}

export function renderClash(nodes = []) {
  const proxies = [];
  for (const n of nodes) {
    const p = nodeToClashProxy(n);
    if (p) proxies.push(p);
  }

  const names = proxies.map((p) => p.name);

  const lines = [];

  // ===== 头部 =====
  lines.push(`# Generated by Lyn autosub`);
  lines.push(`mixed-port: 7890`);
  lines.push(`allow-lan: true`);
  lines.push(`mode: rule`);
  lines.push(`log-level: info`);
  lines.push(`external-controller: '127.0.0.1:9090'`);
  lines.push(``);
  lines.push(`dns:`);
  pushLine(lines, 1, `enable: true`);
  pushLine(lines, 1, `ipv6: false`);
  pushLine(lines, 1, `nameserver:`);
  pushLine(lines, 2, `- 223.5.5.5`);
  pushLine(lines, 2, `- 223.6.6.6`);
  lines.push(``);

  // ===== proxies =====
  lines.push(`proxies:`);
  if (proxies.length === 0) {
    pushLine(lines, 1, `# 没有解析出任何可用节点`);
  } else {
    for (const p of proxies) {
      dumpProxyBlock(lines, p);
    }
  }

  // ===== proxy-groups =====
  lines.push(``);
  lines.push(`proxy-groups:`);
  pushLine(lines, 1, `- name: "🐹Lyn · Node"`);
  pushLine(lines, 2, `type: select`);
  pushLine(lines, 2, `proxies:`);
  if (names.length === 0) {
    pushLine(lines, 3, `- DIRECT`);
  } else {
    pushLine(lines, 3, `- DIRECT`);
    for (const name of names) {
      pushLine(
        lines,
        3,
        `- "${String(name).replace(/"/g, '\\"')}"`
      );
    }
  }

  // ===== rules =====
  lines.push(``);
  lines.push(`rules:`);
  pushLine(lines, 1, `- GEOIP,LAN,DIRECT`);
  pushLine(lines, 1, `- GEOIP,CN,DIRECT`);
  pushLine(lines, 1, `- MATCH,🐹Lyn · Node`);

  return {
    body: lines.join("\n"),
    contentType: "text/yaml; charset=utf-8",
  };
}
