/*
  - 输入：
      Parser.js 标准化后的 Node 数组（Node[]）

  - 当前渲染支持协议：
      • Shadowsocks      → type: "ss"
      • Trojan           → type: "trojan"
      • Hysteria2 / hy2  → type: "hysteria2" / "hy2"
      • VMess            → type: "vmess"

  - 输出：
      Clash / Mihomo 通用 YAML（块状写法）：

        proxies:
          - name: "xxx"
            type: ss / trojan / hysteria2 / vmess
            ...

      默认带一个通用策略组：🐹Lyn · Node

  - 示例调用：
      /autosub?id=你的id&client=clash

  - 说明：
      • SS 支持 obfs 混淆（obfs-local/simple-obfs → plugin: obfs + plugin-opts）
      • hy2 同时输出 password + auth（如需可再调整）
      • VMess 支持：
          - 算法 cipher（scy/security/cipher），默认 auto
          - 传输方式 network：tcp / ws / grpc / kcp / http
          - TLS / servername(SNI)
          - ws-opts / grpc-opts
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
      _type: "ss",
      name,
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
        proxy.plugin = "obfs";
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

  // ---------- VMess ----------
  if (type === "vmess") {
    const uuid = pickString(node.uuid || node.id);
    if (!rawPort || !uuid) return null;

    const proxy = {
      _type: "vmess",
      name,
      server,
      port: rawPort,
      uuid,
    };

    const aid = pickNumber(node.alterId, 0);
    proxy.alterId = Number.isFinite(aid) ? aid : 0;

    // cipher / 加密算法
    const cipher =
      pickString(node.cipher) ||
      pickString(node.security) ||
      pickString(node.scy) ||
      "auto";
    proxy.cipher = cipher || "auto";

    // network
    const netRaw =
      pickString(node.network) ||
      pickString(node.net) ||
      pickString(node.headerType);
    const net = netRaw.toLowerCase();
    if (net) proxy.network = net;

    // TLS
    let tls = false;
    const tlsField =
      pickString(node.tls) || pickString(node.security).toLowerCase();
    if (["tls", "xtls", "reality"].includes(tlsField)) tls = true;
    if (["1", "true", "yes"].includes(tlsField)) tls = true;
    if (tls) proxy.tls = true;

    const sni =
      pickString(node.sni) ||
      pickString(node.servername) ||
      pickString(node["server-name"]);
    if (sni) proxy.servername = sni;

    // UDP
    if (typeof node.udp === "boolean") proxy.udp = node.udp;
    else proxy.udp = true;

    // ws / grpc 细节
    const host = pickString(node.host);
    const path = pickString(node.path);

    if (net === "ws" || net === "websocket") {
      proxy.network = "ws";
      const wsOpts = {};
      if (path) wsOpts.path = path;
      if (host) wsOpts.headers = { Host: host };
      if (Object.keys(wsOpts).length) proxy["ws-opts"] = wsOpts;
    } else if (net === "grpc") {
      proxy.network = "grpc";
      const grpcOpts = {};
      if (path) grpcOpts["grpc-service-name"] = path;
      if (Object.keys(grpcOpts).length) proxy["grpc-opts"] = grpcOpts;
    } else if (net === "tcp" || !net) {
      proxy.network = "tcp";
      // tcp + http header 之类的这里先不展开，后续有需要再加
    }

    return proxy;
  }

  // ---------- Trojan ----------
  if (type === "trojan") {
    const password = pickString(node.password);
    if (!rawPort || !password) return null;

    const proxy = {
      _type: "trojan",
      name,
      server,
      port: rawPort,
      password,
    };

    const sni = pickString(node.sni || node.host);
    if (sni) proxy.sni = sni;

    if (typeof node.skipCertVerify === "boolean") {
      proxy.skipCertVerify = node.skipCertVerify;
    }

    return proxy;
  }

  // ---------- Hysteria2 / hy2 ----------
  if (type === "hysteria2" || type === "hy2") {
    const pwd = pickString(node.password || node.auth);
    if (!pwd) return null;

    const portsStr = pickString(node.ports || node.portRange);
    let mainPort = rawPort;

    if (portsStr) {
      const m = portsStr.match(/^(\d+)/);
      if (m && m[1]) {
        const p2 = Number(m[1]);
        if (Number.isFinite(p2) && p2 > 0) mainPort = p2;
      }
    }

    if (!mainPort) return null;

    const proxy = {
      _type: "hysteria2",
      name,
      server,
      port: mainPort,
      password: pwd,
    };

    if (portsStr) {
      proxy.ports = portsStr;
      proxy.mport = portsStr;
    }

    const sni = pickString(node.sni || node.peer || node.serverName);
    if (sni) proxy.sni = sni;

    if (typeof node.udp === "boolean") {
      proxy.udp = node.udp;
    } else {
      proxy.udp = true;
    }

    if (typeof node.skipCertVerify === "boolean") {
      proxy.skipCertVerify = node.skipCertVerify;
    }

    const obfs = pickString(node.obfs);
    if (obfs) proxy.obfs = obfs;

    return proxy;
  }

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

  // ---------- VMess ----------
  if (proxy._type === "vmess") {
    pushLine(lines, 2, `uuid: ${proxy.uuid}`);
    pushLine(lines, 2, `alterId: ${proxy.alterId}`);
    if (proxy.cipher) pushLine(lines, 2, `cipher: ${proxy.cipher}`);
    if (proxy.udp !== undefined)
      pushLine(lines, 2, `udp: ${proxy.udp ? "true" : "false"}`);
    if (proxy.tls) pushLine(lines, 2, `tls: true`);
    if (proxy.servername)
      pushLine(
        lines,
        2,
        `servername: "${proxy.servername.replace(/"/g, '\\"')}"`
      );
    if (proxy.network) pushLine(lines, 2, `network: ${proxy.network}`);

    if (proxy["ws-opts"]) {
      pushLine(lines, 2, `ws-opts:`);
      if (proxy["ws-opts"].path)
        pushLine(lines, 3, `path: ${proxy["ws-opts"].path}`);
      if (
        proxy["ws-opts"].headers &&
        proxy["ws-opts"].headers.Host
      ) {
        pushLine(lines, 3, `headers:`);
        pushLine(
          lines,
          4,
          `Host: "${proxy["ws-opts"].headers.Host.replace(/"/g, '\\"')}"`
        );
      }
    }

    if (proxy["grpc-opts"]) {
      pushLine(lines, 2, `grpc-opts:`);
      if (proxy["grpc-opts"]["grpc-service-name"])
        pushLine(
          lines,
          3,
          `grpc-service-name: ${proxy["grpc-opts"]["grpc-service-name"]}`
        );
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
    pushLine(lines, 2, `password: ${proxy.password}`);
    if (proxy.ports) pushLine(lines, 2, `ports: ${proxy.ports}`);
    if (proxy.mport) pushLine(lines, 2, `mport: ${proxy.mport}`);
    if (typeof proxy.udp === "boolean") {
      pushLine(lines, 2, `udp: ${proxy.udp ? "true" : "false"}`);
    }
    if (proxy.sni) pushLine(lines, 2, `sni: ${proxy.sni}`);
    if (typeof proxy.skipCertVerify === "boolean") {
      pushLine(
        lines,
        2,
        `skip-cert-verify: ${proxy.skipCertVerify ? "true" : "false"}`
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