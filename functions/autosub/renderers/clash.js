/**
 * Clash / Mihomo 渲染器
 *
 * - 输入：Parser.js 产出的标准化 Node[]
 *
 * - 当前支持的节点类型：
 *   • Shadowsocks ：type = "ss"
 *   • Trojan      ：type = "trojan"
 *   • Hysteria2   ：type = "hysteria2" 或 "hy2"
 *
 * - 典型使用方式：
 *   /autosub?id=你的id&client=clash
 */

/** 安全取字符串 */
function pickString(v, fallback = "") {
  if (v === null || v === undefined) return fallback;
  const s = String(v).trim();
  return s || fallback;
}

/** 安全取数字 */
function pickNumber(v, fallback) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

/**
 * YAML 内联 map 字符串化：
 *   - { key: "val", port: 443, udp: true, plugin-opts: { mode: "http", host: "xxx" } }
 */
function formatInlineMap(obj, indent = "  ") {
  const parts = [];
  for (const [key, value] of Object.entries(obj)) {
    if (value === undefined || value === null || value === "") continue;

    // 特殊处理 plugin-opts：必须是 map，而不是字符串
    if (
      key === "plugin-opts" &&
      typeof value === "object" &&
      !Array.isArray(value)
    ) {
      const innerParts = [];
      for (const [k2, v2] of Object.entries(value)) {
        if (v2 === undefined || v2 === null || v2 === "") continue;

        let innerRendered;
        if (typeof v2 === "number" || typeof v2 === "boolean") {
          innerRendered = String(v2);
        } else {
          const s2 = String(v2)
            .replace(/\\/g, "\\\\")
            .replace(/"/g, '\\"');
          innerRendered = `"${s2}"`;
        }
        innerParts.push(`${k2}: ${innerRendered}`);
      }
      const inner = innerParts.join(", ");
      parts.push(`${key}: { ${inner} }`);
      continue;
    }

    let rendered;
    if (typeof value === "number" || typeof value === "boolean") {
      rendered = String(value);
    } else {
      const s = String(value)
        .replace(/\\/g, "\\\\")
        .replace(/"/g, '\\"');
      rendered = `"${s}"`;
    }
    parts.push(`${key}: ${rendered}`);
  }

  if (!parts.length) return null;
  return `${indent}- { ${parts.join(", ")} }`;
}

/**
 * Node -> Clash proxy 对象
 */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const server = pickString(node.server);
  const port = pickNumber(node.port);
  const nameBase =
    pickString(node.name) || (server && port ? `${server}:${port}` : "");
  const name = nameBase || "Unnamed";

  // ---------- SS ----------
  if (node.type === "ss") {
    const cipher = pickString(node.cipher);
    const password = pickString(node.password);

    if (!server || !port || !cipher || !password) return null;

    const proxy = {
      name,
      type: "ss",
      server,
      port,
      cipher,
      password,
    };

    // plugin + plugin-opts（obfs-local 等）
    if (node.plugin) proxy.plugin = node.plugin;
    if (node.pluginOpts && typeof node.pluginOpts === "object") {
      // 清洗一下 plugin-opts
      const opts = {};
      const src = node.pluginOpts;

      if (src.mode) opts.mode = src.mode;
      if (src.host) opts.host = src.host;
      if (src.uri) opts.uri = src.uri;
      // 其它字段直接透传
      for (const [k, v] of Object.entries(src)) {
        if (["mode", "host", "uri", "raw"].includes(k)) continue;
        if (v === undefined || v === null || v === "") continue;
        opts[k] = v;
      }

      if (Object.keys(opts).length > 0) {
        proxy["plugin-opts"] = opts;
      }
    }

    return proxy;
  }

  // ---------- Trojan ----------
  if (node.type === "trojan") {
    const password = pickString(node.password);
    if (!server || !port || !password) return null;

    const proxy = {
      name,
      type: "trojan",
      server,
      port,
      password,
    };

    const sni = pickString(node.sni || node.host);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    const net = pickString(node.network || node.net || "").toLowerCase();
    if (net === "ws" || net === "websocket") {
      proxy.network = "ws";

      const path = pickString(node.path || node.wsPath || "/");
      const hostHeader = pickString(
        node.host ||
          (node.wsHeaders && node.wsHeaders.Host) ||
          (node.wsHeaders && node.wsHeaders.host)
      );

      const wsOpts = {};
      if (path) wsOpts.path = path;
      if (hostHeader) {
        wsOpts.headers = { Host: hostHeader };
      }

      if (Object.keys(wsOpts).length) {
        proxy["ws-opts"] = wsOpts;
      }
    }

    return proxy;
  }

  // ---------- Hysteria2 / hy2 ----------
  if (node.type === "hysteria2" || node.type === "hy2") {
    const password = pickString(node.password || node.auth);
    if (!server || !port || !password) return null;

    const proxy = {
      name,
      type: "hysteria2",
      server,
      port,
      auth: password,
      password: password,
    };

    const sni = pickString(node.sni || node.peer || node.serverName);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    const ports = pickString(node.ports || node.portRange);
    if (ports) proxy.ports = ports;

    if (typeof node.udp === "boolean") proxy.udp = node.udp;
    if (typeof node.fastOpen === "boolean") {
      proxy["fast-open"] = node.fastOpen;
    }

    const obfs = pickString(node.obfs);
    if (obfs) proxy.obfs = obfs;

    return proxy;
  }

  return null;
}

/**
 * 渲染入口
 */
export function renderClash(nodes = []) {
  const proxies = [];

  for (const n of nodes) {
    const p = nodeToClashProxy(n);
    if (p) proxies.push(p);
  }

  const names = proxies.map((p) => p.name);

  const lines = [];

  // ===== 头部：参考机场风格 =====
  lines.push(`# Generated by Lyn autosub`);
  lines.push(`mixed-port: 7890`);
  lines.push(`allow-lan: true`);
  lines.push(`mode: rule`);
  lines.push(`log-level: info`);
  lines.push(`external-controller: '127.0.0.1:9090'`);
  lines.push(``);
  lines.push(`dns:`);
  lines.push(`  enable: true`);
  lines.push(`  ipv6: false`);
  lines.push(`  nameserver: [223.5.5.5, 223.6.6.6]`);
  lines.push(``);

  // ===== proxies =====
  lines.push(`proxies:`);

  if (proxies.length === 0) {
    lines.push(`  # 没有解析出任何可用节点`);
  } else {
    for (const p of proxies) {
      const line = formatInlineMap(p, "  ");
      if (line) lines.push(line);
    }
  }

  // ===== proxy-groups =====
  lines.push(``);
  lines.push(`proxy-groups:`);
  lines.push(`  - name: "🐹Lyn · Node"`);
  lines.push(`    type: select`);
  lines.push(`    proxies:`);

  if (names.length === 0) {
    lines.push(`      - DIRECT`);
  } else {
    lines.push(`      - DIRECT`);
    for (const name of names) {
      const s = String(name).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      lines.push(`      - "${s}"`);
    }
  }

  // ===== rules =====
  lines.push(``);
  lines.push(`rules:`);
  lines.push(`  - GEOIP,LAN,DIRECT`);
  lines.push(`  - GEOIP,CN,DIRECT`);
  lines.push(`  - MATCH,🐹Lyn · Node`);

  return {
    body: lines.join("\n"),
    contentType: "text/yaml; charset=utf-8",
  };
}
