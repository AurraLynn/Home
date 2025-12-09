/**
 * Clash / Mihomo 渲染器（块状 YAML 版本）
 *
 * - 支持节点类型：
 *   • Shadowsocks ：type = "ss"
 *   • Trojan      ：type = "trojan"
 *   • Hysteria2   ：type = "hysteria2" 或 "hy2"
 *
 * - 输出为最兼容的块状 YAML，避免 { ... } 内联写法
 * - SS 支持 obfs 混淆（plugin=obfs / simple-obfs / obfs-local）
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

/** Node -> JS proxy 对象（内部结构） */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();
  const server = pickString(node.server);
  const port = pickNumber(node.port);
  const nameBase =
    pickString(node.name) || (server && port ? `${server}:${port}` : "");
  const name = nameBase || "Unnamed";

  if (!server || !port) return null;

  // ---------- SS ----------
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

    // 插件：obfs / simple-obfs / obfs-local
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

  // ---------- 极简 Trojan ----------
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

    // 不再输出 network / ws-opts / headers，防止兼容性问题
    return proxy;
  }

  // ---------- Hysteria2 / hy2 ----------
  if (type === "hysteria2" || type === "hy2") {
    // 统一把密码收敛到 password 字段
    const pwd = pickString(node.password || node.auth);
    if (!pwd) return null;

    const proxy = {
      _type: "hysteria2",
      name,
      server,
      port,
      // ★ 只输出 password，不再输出 auth，避免有客户端不认 auth
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

  return null;
}

/** 把 proxy 对象输出为块状 YAML */
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
  } else if (proxy._type === "trojan") {
    pushLine(lines, 2, `password: ${proxy.password}`);
    if (proxy.sni) pushLine(lines, 2, `sni: ${proxy.sni}`);
    if (typeof proxy.skipCertVerify === "boolean") {
      pushLine(
        lines,
        2,
        `skip-cert-verify: ${proxy.skipCertVerify ? "true" : "false"}`
      );
    }
  } else if (proxy._type === "hysteria2") {
    // ★ 这里只写 password
    pushLine(lines, 2, `password: ${proxy.password}`);
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
