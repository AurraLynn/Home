/*
  - 输入：
      Parser.js 标准化后的 Node 数组（Node[]）

  - 当前渲染支持协议：
      • Shadowsocks      → type: "ss"
      • Trojan           → type: "trojan"
      • Hysteria2 / hy2  → type: "hysteria2" / "hy2"

  - 输出：
      Clash / Mihomo / Clash Verge 通用 YAML
      proxies 使用「内联写法」：
        - { name: "xxx", type: "ss", server: "...", ... }

  - 示例调用：
      /autosub?id=你的id&client=clash
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

/**
 * 内联 map 格式化：
 *  - obj: { name: "...", port: 443, plugin-opts: { mode: "http", host: "xx" } }
 *  → '  - { name: "xxx", port: 443, plugin-opts: { mode: "http", host: "xx" } }'
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

/** Node -> 内部 proxy 对象（_type 区分协议） */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();
  const server = pickString(node.server);
  const rawPort = pickNumber(node.port);
  const nameBase =
    pickString(node.name) || (server && rawPort ? `${server}:${rawPort}` : "");
  const name = nameBase || "Unnamed";

  if (!server) return null;

  // ---------- Shadowsocks ----------
  if (type === "ss") {
    const cipher = pickString(node.cipher || node.method);
    const password = pickString(node.password);

    if (!rawPort || !cipher || !password) return null;

    const proxy = {
      name,
      type: "ss",
      server,
      port: rawPort,
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
        proxy["plugin-opts"] = opts;
      }
    }

    return proxy;
  }

  // ---------- Trojan（极简版） ----------
  if (type === "trojan") {
    const password = pickString(node.password);
    if (!rawPort || !password) return null;

    const proxy = {
      name,
      type: "trojan",
      server,
      port: rawPort,
      password,
    };

    const sni = pickString(node.sni || node.host);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    return proxy;
  }

  // ---------- Hysteria2 / hy2 ----------
  if (type === "hysteria2" || type === "hy2") {
    // 收敛到 password 字段；从 node.password / node.auth 任意一方取
    const pwd = pickString(node.password || node.auth);
    if (!pwd) return null;

    // 端口段字符串，如 "35000-39000"
    const portsStr = pickString(node.ports || node.portRange);
    let mainPort = rawPort;

    // 如果有 ports，优先用区间起始值作为主 port（对齐机场）
    if (portsStr) {
      const m = portsStr.match(/^(\d+)/);
      if (m && m[1]) {
        const p2 = Number(m[1]);
        if (Number.isFinite(p2) && p2 > 0) mainPort = p2;
      }
    }

    if (!mainPort) return null;

    const proxy = {
      name,
      type: "hysteria2",
      server,
      port: mainPort,
      password: pwd,
    };

    if (portsStr) {
      proxy.ports = portsStr; // Clash 本身会识别 ports
      proxy.mport = portsStr; // 对齐部分机场写法
    }

    const sni = pickString(node.sni || node.peer || node.serverName);
    if (sni) proxy.sni = sni;

    // udp：默认 true，只在明确为 false 时才关
    if (typeof node.udp === "boolean") {
      proxy.udp = node.udp;
    } else {
      proxy.udp = true;
    }

    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    const obfs = pickString(node.obfs);
    if (obfs) proxy.obfs = obfs;

    return proxy;
  }

  // 其它协议暂不渲染进 Clash
  return null;
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
  lines.push(`external-controller: "127.0.0.1:9090"`);
  lines.push(``);
  lines.push(`dns:`);
  lines.push(`  enable: true`);
  lines.push(`  ipv6: false`);
  lines.push(`  nameserver: [223.5.5.5, 223.6.6.6]`);
  lines.push(``);

  // ===== proxies：内联写法 =====
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
