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
      Clash / Mihomo 通用配置（块状 YAML）：
        port / socks-port / dns / rules 等基础配置
        proxies:
          - name: "..."
            type: ss / vmess / vless / trojan / hysteria2
            ...

  - 调用示例：
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

function yamlQuote(str) {
  const s = String(str);
  // 简单转义双引号和反斜杠
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/** 缩进 + 一行文本 */
function pushLine(lines, indentLevel, text) {
  const indent = "  ".repeat(indentLevel);
  lines.push(indent + text);
}

/**
 * Node -> 内部 proxy 对象（_type 区分协议）
 * 统一结构，后面 dumpProxyBlock 负责输出具体 YAML
 */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();

  // 关键修正：server / port 容错
  // 很多解析器只填了 host / add / server_port，我们在这里兜一层
  const server = pickString(node.server || node.host || node.add);
  const port = pickNumber(node.port ?? node.server_port, 0);

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

  // ===== VMess =====
  if (type === "vmess") {
    const uuid = pickString(node.uuid || node.id);
    if (!uuid) return null;

    const proxy = {
      _type: "vmess",
      name,
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
      _type: "vless",
      name,
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

    const obfsHy = pickString(node.obfs);
    if (obfsHy) proxy.obfs = obfsHy;

    return proxy;
  }

  // 未识别协议
  return null;
}

/** 输出单个 proxy 的块状 YAML */
function dumpProxyBlock(lines, proxy) {
  // 通用字段
  pushLine(lines, 1, `- name: ${yamlQuote(proxy.name)}`);
  pushLine(lines, 2, `type: ${proxy._type}`);
  pushLine(lines, 2, `server: ${proxy.server}`);
  pushLine(lines, 2, `port: ${proxy.port}`);

  // ===== SS =====
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

  // ===== VMess =====
  if (proxy._type === "vmess") {
    pushLine(lines, 2, `uuid: ${proxy.uuid}`);
    pushLine(lines, 2, `alterId: ${proxy.alterId}`);
    if (proxy.cipher) pushLine(lines, 2, `cipher: ${proxy.cipher}`);
    if (proxy.udp !== undefined)
      pushLine(lines, 2, `udp: ${proxy.udp ? "true" : "false"}`);
    if (proxy.tls) pushLine(lines, 2, `tls: true`);
    if (proxy.servername)
      pushLine(lines, 2, `servername: ${yamlQuote(proxy.servername)}`);
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
          `Host: ${yamlQuote(proxy["ws-opts"].headers.Host)}`
        );
      }
    }

    if (proxy["http-opts"]) {
      pushLine(lines, 2, `http-opts:`);
      if (proxy["http-opts"].path) {
        pushLine(lines, 3, `path:`);
        for (const p of proxy["http-opts"].path) {
          pushLine(lines, 4, `- ${p}`);
        }
      }
      if (proxy["http-opts"].headers) {
        pushLine(lines, 3, `headers:`);
        const hdrs = proxy["http-opts"].headers;
        for (const key of Object.keys(hdrs)) {
          const arr = hdrs[key] || [];
          if (!arr.length) continue;
          pushLine(lines, 4, `${key}:`);
          for (const v of arr) {
            pushLine(lines, 5, `- ${yamlQuote(v)}`);
          }
        }
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

  // ===== VLESS =====
  if (proxy._type === "vless") {
    pushLine(lines, 2, `uuid: ${proxy.uuid}`);
    if (proxy.udp !== undefined)
      pushLine(lines, 2, `udp: ${proxy.udp ? "true" : "false"}`);
    if (proxy.flow) pushLine(lines, 2, `flow: ${proxy.flow}`);
    if (proxy.tls) pushLine(lines, 2, `tls: true`);
    if (proxy.servername)
      pushLine(lines, 2, `servername: ${yamlQuote(proxy.servername)}`);

    if (proxy.alpn && Array.isArray(proxy.alpn) && proxy.alpn.length) {
      pushLine(lines, 2, `alpn:`);
      for (const a of proxy.alpn) {
        pushLine(lines, 3, `- ${a}`);
      }
    }

    if (proxy["client-fingerprint"]) {
      pushLine(
        lines,
        2,
        `client-fingerprint: ${proxy["client-fingerprint"]}`
      );
    }

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
          `Host: ${yamlQuote(proxy["ws-opts"].headers.Host)}`
        );
      }
    }

    if (proxy["http-opts"]) {
      pushLine(lines, 2, `http-opts:`);
      if (proxy["http-opts"].path) {
        pushLine(lines, 3, `path:`);
        for (const p of proxy["http-opts"].path) {
          pushLine(lines, 4, `- ${p}`);
        }
      }
      if (proxy["http-opts"].headers) {
        pushLine(lines, 3, `headers:`);
        const hdrs = proxy["http-opts"].headers;
        for (const key of Object.keys(hdrs)) {
          const arr = hdrs[key] || [];
          if (!arr.length) continue;
          pushLine(lines, 4, `${key}:`);
          for (const v of arr) {
            pushLine(lines, 5, `- ${yamlQuote(v)}`);
          }
        }
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

    if (proxy["reality-opts"]) {
      pushLine(lines, 2, `reality-opts:`);
      if (proxy["reality-opts"]["public-key"])
        pushLine(
          lines,
          3,
          `public-key: ${proxy["reality-opts"]["public-key"]}`
        );
      if (proxy["reality-opts"]["short-id"])
        pushLine(
          lines,
          3,
          `short-id: ${yamlQuote(proxy["reality-opts"]["short-id"])}`
        );
      if (proxy["reality-opts"]["spider-x"])
        pushLine(
          lines,
          3,
          `spider-x: ${yamlQuote(proxy["reality-opts"]["spider-x"])}`
        );
    }

    return;
  }

  // ===== Trojan =====
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

    if (proxy.network) {
      pushLine(lines, 2, `network: ${proxy.network}`);
    }

    if (proxy["ws-opts"]) {
      pushLine(lines, 2, `ws-opts:`);
      if (proxy["ws-opts"].path)
        pushLine(lines, 3, `path: ${proxy["ws-opts"].path}`);
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

    if (proxy["reality-opts"]) {
      pushLine(lines, 2, `reality-opts:`);
      if (proxy["reality-opts"]["public-key"])
        pushLine(
          lines,
          3,
          `public-key: ${proxy["reality-opts"]["public-key"]}`
        );
      if (proxy["reality-opts"]["short-id"])
        pushLine(
          lines,
          3,
          `short-id: ${yamlQuote(proxy["reality-opts"]["short-id"])}`
        );
      if (proxy["reality-opts"]["spider-x"])
        pushLine(
          lines,
          3,
          `spider-x: ${yamlQuote(proxy["reality-opts"]["spider-x"])}`
        );
    }

    return;
  }

  // ===== Hysteria2 =====
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
    return;
  }
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
  pushLine(lines, 1, `enable: true`);
  pushLine(lines, 1, `listen: 0.0.0.0:53`);
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
  pushLine(lines, 1, `- name: ${yamlQuote("🐹 · Select")}`);
  pushLine(lines, 2, `type: select`);
  pushLine(lines, 2, `proxies:`);
  if (names.length === 0) {
    pushLine(lines, 3, `- DIRECT`);
  } else {
    pushLine(lines, 3, `- DIRECT`);
    for (const name of names) {
      pushLine(lines, 3, `- ${yamlQuote(name)}`);
    }
  }

  // ===== rules =====
  lines.push(``);
  lines.push(`rules:`);
  pushLine(lines, 1, `- GEOIP,LAN,DIRECT`);
  pushLine(lines, 1, `- GEOIP,CN,DIRECT`);
  pushLine(lines, 1, `- MATCH,🐹 · Select`);

  return {
    body: lines.join("\n"),
    contentType: "text/yaml; charset=utf-8",
  };
}
