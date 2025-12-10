/*
  functions/autosub/renderers/clash.js

  - 输入：
      Parser.js / Normalizer.js 产出的 Node[] 标准节点列表

  - 当前支持协议类型（Node.type）：
      • ss
      • vmess
      • vless
      • trojan
      • hysteria2 / hy2

  - 输出：
      Clash / Mihomo 通用配置：
        • 头部内置一个简单可用的配置（port / dns / 规则）
        • proxies 使用 JSON 内联写法，兼容 FIClash / NekoBox / Clash Verge 等：
            proxies:
              - {"name":"HK 02","type":"ss","server":"...","port":11411,"cipher":"...","password":"..."}

  - client 用法（示例）：
      https://aura.us.kg/autosub?id=你的id&client=clash
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
 * Node -> Clash 代理对象（JSON 内联用）
 * 返回形如：
 *   { name, type, server, port, ... }
 */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();
  const server = pickString(node.server);
  const port = pickNumber(node.port);
  const nameBase =
    pickString(node.name) || (server && port ? `${server}:${port}` : "");
  const name = nameBase || "Unnamed";

  if (!server || !port) return null;

  // ===== Shadowsocks =====
  if (type === "ss") {
    const cipher = pickString(node.cipher || node.method);
    const password = pickString(node.password);
    if (!cipher || !password) return null;

    const proxy = {
      name,
      type: "ss",
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
        proxy["plugin-opts"] = opts;
      }
    }

    return proxy;
  }

  // ===== VMess =====
  if (type === "vmess") {
    const uuid = pickString(node.uuid || node.id);
    if (!uuid) return null;

    const proxy = {
      name,
      type: "vmess",
      server,
      port,
      uuid,
    };

    const aid = pickNumber(node.alterId, 0);
    proxy.alterId = Number.isFinite(aid) ? aid : 0;

    const cipher =
      pickString(node.cipher) ||
      pickString(node.security) ||
      pickString(node.scy) ||
      "auto";
    proxy.cipher = cipher || "auto";

    // UDP：默认 true
    if (typeof node.udp === "boolean") proxy.udp = node.udp;
    else proxy.udp = true;

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

    const host = pickString(node.host);
    const path = pickString(node.path);
    const obfs = pickString(node.obfs).toLowerCase();
    const netRaw = pickString(node.network || node.net || "");
    const net = netRaw.toLowerCase();

    if (net === "ws" || obfs === "websocket" || obfs === "ws") {
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
    } else if (net === "http" || obfs === "http") {
      // vmess + tcp + http 混淆
      proxy.network = "http";
      const httpOpts = {};
      const finalPath = path || "/";
      httpOpts.path = [finalPath];
      if (host) {
        httpOpts.headers = {
          Host: [host],
        };
      }
      proxy["http-opts"] = httpOpts;
    } else {
      proxy.network = "tcp";
    }

    return proxy;
  }

  // ===== VLESS =====
  if (type === "vless") {
    const uuid = pickString(node.uuid || node.id);
    if (!uuid) return null;

    const proxy = {
      name,
      type: "vless",
      server,
      port,
      uuid,
    };

    if (typeof node.udp === "boolean") proxy.udp = node.udp;
    else proxy.udp = true;

    const flow = pickString(node.flow);
    if (flow) proxy.flow = flow;

    // tls / security
    let tls = false;
    const security = pickString(node.security).toLowerCase();
    if (["tls", "xtls", "reality"].includes(security)) tls = true;
    if (tls || node.tls === true) proxy.tls = true;

    const sni =
      pickString(node.sni) ||
      pickString(node.servername) ||
      pickString(node.host);
    if (sni) proxy.servername = sni;

    const alpn = pickString(node.alpn);
    if (alpn) proxy.alpn = [alpn];

    const fp =
      pickString(node.clientFingerprint) ||
      pickString(node.fp) ||
      pickString(node.fingerprint);
    if (fp) proxy["client-fingerprint"] = fp;

    const host = pickString(node.host);
    const path = pickString(node.path);
    const netRaw = pickString(node.network || node.type || "");
    const net = netRaw.toLowerCase();

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
    } else if (net === "http" || net === "h2" || net === "httpupgrade") {
      proxy.network = "http";
      const httpOpts = {};
      const finalPath = path || "/";
      httpOpts.path = [finalPath];
      if (host) {
        httpOpts.headers = {
          Host: [host],
        };
      }
      proxy["http-opts"] = httpOpts;
    } else {
      proxy.network = "tcp";
    }

    // Reality
    const pbk =
      pickString(node.realityPublicKey) ||
      pickString(node.publicKey) ||
      pickString(node.pbk);
    const sid =
      pickString(node.realityShortId) ||
      pickString(node.shortId) ||
      pickString(node.sid);
    const spx =
      pickString(node.realitySpiderX) ||
      pickString(node.spiderX) ||
      pickString(node.spx);

    if (pbk || sid || spx) {
      const reality = {};
      if (pbk) reality["public-key"] = pbk;
      if (sid) reality["short-id"] = sid;
      if (spx) reality["spider-x"] = spx;
      proxy["reality-opts"] = reality;
    }

    return proxy;
  }

  // ===== Trojan =====
  if (type === "trojan") {
    const password = pickString(node.password);
    if (!password) return null;

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

    const net = pickString(node.network).toLowerCase();
    const path = pickString(node.path);

    if (net === "grpc") {
      proxy.network = "grpc";
      if (path) {
        proxy["grpc-opts"] = {
          "grpc-service-name": path,
        };
      }
    } else if (net === "ws") {
      proxy.network = "ws";
      const wsOpts = {};
      if (path) wsOpts.path = path;
      if (Object.keys(wsOpts).length) proxy["ws-opts"] = wsOpts;
    }

    // Reality
    const pbk =
      pickString(node.realityPublicKey) ||
      pickString(node.publicKey) ||
      pickString(node.pbk);
    const sid =
      pickString(node.realityShortId) ||
      pickString(node.shortId) ||
      pickString(node.sid);
    const spx =
      pickString(node.realitySpiderX) ||
      pickString(node.spiderX) ||
      pickString(node.spx);

    if (pbk || sid || spx) {
      const reality = {};
      if (pbk) reality["public-key"] = pbk;
      if (sid) reality["short-id"] = sid;
      if (spx) reality["spider-x"] = spx;
      proxy["reality-opts"] = reality;
    }

    return proxy;
  }

  // ===== Hysteria2 / hy2 =====
  if (type === "hysteria2" || type === "hy2") {
    const pwd = pickString(node.password || node.auth);
    if (!pwd) return null;

    const portsStr = pickString(node.ports || node.portRange);
    let mainPort = port;

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
      // 同时输出 password + auth，让不同内核自己选用
      password: pwd,
      auth: pwd,
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
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    const obfsHy = pickString(node.obfs);
    if (obfsHy) proxy.obfs = obfsHy;

    return proxy;
  }

  // 未识别协议
  return null;
}

export function renderClash(nodes = []) {
  const proxies = [];
  const stats = {
    ss: 0,
    vmess: 0,
    vless: 0,
    trojan: 0,
    hysteria2: 0,
    hy2: 0,
    unknown: 0,
  };

  for (const n of nodes || []) {
    if (!n) continue;
    const t = String(n.type || "").toLowerCase();
    if (stats.hasOwnProperty(t)) stats[t] += 1;
    else stats.unknown += 1;

    const p = nodeToClashProxy(n);
    if (p) proxies.push(p);
  }

  const names = proxies.map((p) => p.name);

  const lines = [];

  // ===== 头部 =====
  lines.push(`# Generated by Lyn autosub`);
  lines.push(
    `# stats: ss=${stats.ss}, vmess=${stats.vmess}, vless=${stats.vless}, trojan=${stats.trojan}, hy2=${stats.hysteria2 + stats.hy2}, unknown=${stats.unknown}`
  );
  lines.push(`port: 7890`);
  lines.push(`socks-port: 7891`);
  lines.push(`mode: Rule`);
  lines.push(`allow-lan: true`);
  lines.push(`log-level: info`);
  lines.push(``);
  lines.push(`dns:`);
  lines.push(`  enable: true`);
  lines.push(`  listen: 0.0.0.0:53`);
  lines.push(`  ipv6: false`);
  lines.push(`  nameserver:`);
  lines.push(`    - 223.5.5.5`);
  lines.push(`    - 223.6.6.6`);
  lines.push(``);
  lines.push(`proxies:`);

  if (proxies.length === 0) {
    lines.push(`  # no supported proxies parsed yet`);
  } else {
    for (const p of proxies) {
      lines.push(`  - ${JSON.stringify(p)}`);
    }
  }

  lines.push(``);
  lines.push(`proxy-groups:`);
  lines.push(`  - name: "🐹Lyn · Node"`);
  lines.push(`    type: select`);
  lines.push(`    proxies:`);
  if (names.length === 0) {
    lines.push(`      - "DIRECT"`);
  } else {
    lines.push(`      - "DIRECT"`);
    for (const name of names) {
      lines.push(`      - "${String(name).replace(/"/g, '\\"')}"`);
    }
  }

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