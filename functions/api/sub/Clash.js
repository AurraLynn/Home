// functions/api/sub/Clash.js
//
// 支持输入：
// - URL 格式
// - URL / Base64 混合格式
// - Base64（单条、多条）
//
// 支持输出（仅白名单协议）：
// - Shadowsocks / UDP、HTTP+UDP
// - Trojan / UDP
// - Hysteria2 / UDP
// - VMess / UDP、HTTP+UDP、WS+UDP
// - VLESS / UDP、XTLS-RPRX-VISION+UDP、WS+UDP

export async function onRequestPost(context) {
  return handleRequest(context);
}

export async function onRequestGet(context) {
  return handleRequest(context);
}

async function handleRequest({ request }) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "*",
      },
    });
  }

  let text;
  const url = new URL(request.url);
  const source = url.searchParams.get("source") || "raw";

  if (request.method === "GET") {
    const data = url.searchParams.get("data");
    if (!data) {
      return new Response("missing data", {
        status: 400,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
    try {
      text = decodeURIComponent(data);
    } catch (_e) {
      text = data;
    }
  } else {
    const contentType = request.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      try {
        const body = await request.json();
        if (!body || typeof body.text !== "string") {
          return new Response("invalid json body", {
            status: 400,
            headers: { "content-type": "text/plain; charset=utf-8" },
          });
        }
        text = body.text;
      } catch (_e) {
        return new Response("invalid json body", {
          status: 400,
          headers: { "content-type": "text/plain; charset=utf-8" },
        });
      }
    } else {
      text = await request.text();
    }
  }

  if (!text || typeof text !== "string") {
    return new Response("no text", {
      status: 400,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 尝试把整个当订阅 Base64 解一层
  const compact = text.replace(/\s+/g, "");
  const decodedWhole = safeBase64Decode(compact);
  if (
    decodedWhole &&
    (decodedWhole.includes("ss://") ||
      decodedWhole.includes("vmess://") ||
      decodedWhole.includes("vless://") ||
      decodedWhole.includes("trojan://") ||
      decodedWhole.includes("hysteria2://") ||
      decodedWhole.includes("hy2://"))
  ) {
    text = decodedWhole;
  }

  const nodes = parseWhitelistNodes(text);

  if (!nodes.length) {
    return new Response("# no nodes", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (n.type === "ss") {
      // Shadowsocks
      const obj = {
        type: "ss",
        server: n.server,
        port: n.port,
        cipher: n.cipher,
        password: n.password,
        name: n.name,
      };

      if ((n.plugin || "").toLowerCase() === "obfs" && n.pluginMode) {
        obj.plugin = "obfs";
        const opts = { mode: n.pluginMode }; // http / tls
        if (n.pluginHost) {
          opts.host = n.pluginHost;
        }
        obj["plugin-opts"] = opts;
      }

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "trojan") {
      // Trojan
      const obj = {
        type: "trojan",
        server: n.server,
        port: n.port,
        password: n.password,
        sni: n.sni || n.server,
        "skip-cert-verify": n.skipCertVerify === true,
        name: n.name,
      };
      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "hysteria2") {
      // Hysteria2（按你给的 password + tfo 格式）
      const obj = {
        type: "hysteria2",
        name: n.name,
        server: n.server,
        port: n.port,
        "skip-cert-verify": n.skipCertVerify === true,
        tfo: !n.ports, // 有 ports 就认为关闭 tfo
        password: n.auth,
      };
      if (n.ports) obj.ports = n.ports;
      if (n.sni) obj.sni = n.sni;

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "vmess") {
      // VMess
      const obj = {
        type: "vmess",
        name: n.name,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        cipher: n.cipher || "auto",
        alterId: n.alterId || 0,
        tls: !!n.tls,
      };

      if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
          headers: {
            Host: n.hostHeader || n.server,
          },
        };
      } else if (n.network === "http") {
        obj.network = "http";
        obj["http-opts"] = {
          path: [n.path || "/"],
          headers: {
            Host: [n.hostHeader || n.server],
          },
        };
      } else {
        obj.network = "tcp";
      }

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "vless") {
      // VLESS（Reality / XTLS / WS）
      const obj = {
        type: "vless",
        name: n.name,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        tls: !!n.tls,
        "skip-cert-verify": n.skipCertVerify === true,
        network: n.network || "tcp",
      };

      if (n.servername) {
        obj.servername = n.servername;
      }

      // Reality
      if (n.pbk) {
        obj["reality-opts"] = {
          "public-key": n.pbk,
        };
        if (n.sid) {
          obj["reality-opts"]["short-id"] = n.sid;
        }
      }

      if (n.flow) {
        obj.flow = n.flow;
      }

      if (n.network === "ws") {
        obj["ws-opts"] = {
          path: n.path || "/",
          headers: {},
        };
        if (n.hostHeader) {
          obj["ws-opts"].headers.Host = n.hostHeader;
        }
      }

      lines.push("  - " + JSON.stringify(obj));
    }
  }

  return new Response(lines.join("\n"), {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

/* ================= 主解析：从原始文本中提取白名单协议节点 ================= */

function parseWhitelistNodes(text) {
  const tokens = text
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean);

  const nodes = [];
  const seen = new Set();

  for (const token of tokens) {
    let s = token;
    try {
      const d1 = decodeURIComponent(s);
      if (
        d1.startsWith("ss://") ||
        d1.startsWith("vmess://") ||
        d1.startsWith("vless://") ||
        d1.startsWith("trojan://") ||
        d1.startsWith("hysteria2://") ||
        d1.startsWith("hy2://")
      ) {
        s = d1;
      }
    } catch (_e) {}

    const lower = s.toLowerCase();

    if (lower.startsWith("ss://")) {
      const uri = s;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseSS(uri);
      if (!n) continue;

      const shape = getSsShape(n);
      if (shape !== "ss-udp" && shape !== "ss-http-udp") continue;

      nodes.push(n);
    } else if (lower.startsWith("trojan://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseTrojan(uri);
      if (!n) continue;
      nodes.push(n);
    } else if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseHysteria2(uri);
      if (!n) continue;
      nodes.push(n);
    } else if (lower.startsWith("vmess://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseVMess(uri);
      if (!n) continue;

      const shape = getVmessShape(n);
      if (
        shape !== "vmess-udp" &&
        shape !== "vmess-http-udp" &&
        shape !== "vmess-ws-udp"
      ) {
        continue;
      }

      nodes.push(n);
    } else if (lower.startsWith("vless://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseVless(uri);
      if (!n) continue;

      const shape = getVlessShape(n);
      if (
        shape !== "vless-udp" &&
        shape !== "vless-xtls-udp" &&
        shape !== "vless-ws-udp"
      ) {
        continue;
      }

      // vless/udp, vless/xtls-rprx-vision/udp, vless/websocket/udp
      nodes.push(n);
    }
  }

  return nodes;
}

/* ================= Shadowsocks 解析：ss:// ================= */

function getSsShape(n) {
  const plugin = (n.plugin || "").toLowerCase();
  const mode = (n.pluginMode || "").toLowerCase();

  if (!plugin || plugin === "none") {
    return "ss-udp";
  }
  if (plugin === "obfs" && mode === "http") {
    return "ss-http-udp";
  }
  return "unknown";
}

function parseSS(uri) {
  try {
    if (!uri.toLowerCase().startsWith("ss://")) return null;

    let u = uri.replace(/^ss:\/\//i, "");

    // 节点名
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.substring(hashIndex + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIndex);
    }

    // main + query
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.substring(0, qIndex);
      queryStr = u.substring(qIndex + 1);
    }

    // main 可能是 Base64(method:password@host:port)
    const basicDecoded = safeBase64Decode(main);
    let method = "";
    let password = "";
    let host = "";
    let port = 0;

    if (basicDecoded && basicDecoded.includes("@")) {
      // Base64 形态
      const atIndex = basicDecoded.lastIndexOf("@");
      const userPart = basicDecoded.substring(0, atIndex);
      const hostPart = basicDecoded.substring(atIndex + 1);

      const colonIndex = userPart.indexOf(":");
      method = userPart.substring(0, colonIndex);
      password = userPart.substring(colonIndex + 1);

      const pm = hostPart.match(/:(\d+)$/);
      if (!pm) return null;
      port = parseInt(pm[1], 10);
      host = hostPart.substring(0, pm.index);
    } else {
      // 可能是 ss://method:password@host:port?...
      const atIndex = main.lastIndexOf("@");
      if (atIndex === -1) return null;

      const userPart = main.substring(0, atIndex);
      const hostPart = main.substring(atIndex + 1);

      const colonIndex = userPart.indexOf(":");
      method = userPart.substring(0, colonIndex);
      password = userPart.substring(colonIndex + 1);

      const pm = hostPart.match(/:(\d+)$/);
      if (!pm) return null;
      port = parseInt(pm[1], 10);
      host = hostPart.substring(0, pm.index);
    }

    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const qObfs = search.get("obfs") || "";
      const qObfsHost = search.get("obfs-host") || "";
      if (qObfs) pluginMode = qObfs;
      if (qObfsHost) {
        try {
          pluginHost = decodeURIComponent(qObfsHost);
        } catch (_e) {
          pluginHost = qObfsHost;
        }
      }

      const pluginParam = search.get("plugin") || "";
      if (pluginParam) {
        const segs = pluginParam.split(";");
        plugin = segs[0] || "obfs";
        for (const seg of segs.slice(1)) {
          const [k, v] = seg.split("=", 2);
          if (k === "obfs") {
            pluginMode = v;
          } else if (k === "obfs-host") {
            pluginHost = v;
          }
        }
      }
    }

    if (!name) {
      name = host + ":" + port;
    }

    return {
      raw: uri,
      type: "ss",
      server: host,
      port,
      cipher: method,
      password,
      plugin: plugin || (pluginMode ? "obfs" : ""),
      pluginMode,
      pluginHost,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= Trojan 解析：trojan:// ================= */

function parseTrojan(uri) {
  try {
    if (!uri.toLowerCase().startsWith("trojan://")) return null;

    let u = uri.replace(/^trojan:\/\//i, "").trim();

    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    let mainPart = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      mainPart = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    // mainPart: password@host:port
    const atIdx = mainPart.lastIndexOf("@");
    if (atIdx === -1) return null;

    const password = mainPart.substring(0, atIdx);
    const hostPort = mainPart.substring(atIdx + 1);

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let sni = "";
    let skipCertVerify = false;
    let ports = "";

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const peer = search.get("peer");
      if (peer) {
        try {
          sni = decodeURIComponent(peer);
        } catch (_e) {
          sni = peer;
        }
      }

      const sniParam = search.get("sni");
      if (sniParam) {
        try {
          sni = decodeURIComponent(sniParam);
        } catch (_e) {
          sni = sniParam;
        }
      }

      const allowInsecure = search.get("allow-insecure") || search.get("allowInsecure");
      if (allowInsecure === "1" || allowInsecure === "true") {
        skipCertVerify = true;
      }

      const portRange = search.get("ports") || "";
      if (portRange) {
        ports = portRange;
      }
    }

    if (!name) {
      name = host + ":" + port;
    }

    return {
      raw: uri,
      type: "trojan",
      server: host,
      port,
      password,
      sni,
      skipCertVerify,
      ports,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= Hysteria2 解析：hysteria2:// / hy2:// ================= */

function parseHysteria2(uri) {
  try {
    let s = uri.trim();

    // 可能整条再 encode 一次，先尝试解一层
    try {
      const d1 = decodeURIComponent(s);
      if (d1.startsWith("hysteria2://") || d1.startsWith("hy2://")) {
        s = d1;
      }
    } catch (_e) {}

    let lower = s.toLowerCase();
    if (!lower.startsWith("hysteria2://") && !lower.startsWith("hy2://")) {
      return null;
    }

    s = s.replace(/^hysteria2:\/\//i, "").replace(/^hy2:\/\//i, "");

    let name = "";
    const hashIdx = s.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = s.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      s = s.substring(0, hashIdx);
    }

    let mainPart = s;
    let queryStr = "";
    const qIdx = s.indexOf("?");
    if (qIdx !== -1) {
      mainPart = s.substring(0, qIdx);
      queryStr = s.substring(qIdx + 1);
    }

    // mainPart: auth@host:port
    const atIdx = mainPart.lastIndexOf("@");
    if (atIdx === -1) return null;

    const auth = mainPart.substring(0, atIdx);
    const hostPort = mainPart.substring(atIdx + 1);

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let sni = "";
    let skipCertVerify = false;
    let ports = "";

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const peer = search.get("peer");
      if (peer) {
        try {
          sni = decodeURIComponent(peer);
        } catch (_e) {
          sni = peer;
        }
      }

      const sniParam = search.get("sni");
      if (sniParam) {
        try {
          sni = decodeURIComponent(sniParam);
        } catch (_e) {
          sni = sniParam;
        }
      }

      const insecure = search.get("insecure");
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }

      const portRange = search.get("ports") || "";
      if (portRange) {
        ports = portRange;
      }
    }

    if (!name) {
      name = host + ":" + port;
    }

    return {
      raw: uri,
      type: "hysteria2",
      server: host,
      port,
      auth,
      sni,
      skipCertVerify,
      ports,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= VMess 解析：vmess:// ================= */

function getVmessShape(n) {
  if (n.network === "http") return "vmess-http-udp";
  if (n.network === "ws") return "vmess-ws-udp";
  return "vmess-udp";
}

function parseVMess(uri) {
  try {
    if (!uri.toLowerCase().startsWith("vmess://")) return null;

    // 去掉前缀与尾部空白
    let u = uri.replace(/^vmess:\/\//i, "").replace(/\s+$/g, "");

    // 先从 # 中提取备注
    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    // mainPart + queryStr
    let mainPart = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      mainPart = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    // 先尝试按 Base64 解码（老 vmess 常用写法）
    const decodedMainRaw = safeBase64Decode(mainPart);
    const candidate = (decodedMainRaw && decodedMainRaw.trim())
      ? decodedMainRaw.trim()
      : mainPart.trim();

    // ========== 分支 1：JSON Base64 vmess ==========
    // 例如：vmess:// base64({"v":"2","ps":"...","add":"...","port":"..."...})
    if (candidate.startsWith("{")) {
      let obj;
      try {
        obj = JSON.parse(candidate);
      } catch (_e) {
        return null;
      }

      const host = obj.add || "0.0.0.0";
      const port = obj.port ? (parseInt(obj.port, 10) || 443) : 443;
      const uuid = obj.id || "";
      const cipher = obj.scy || "auto";
      const alterId = obj.aid != null ? (parseInt(obj.aid, 10) || 0) : 0;
      const network = obj.net || "tcp";
      const path = obj.path || "/";
      const hostHeader = obj.host || "";

      let tls = false;
      const tlsVal = (obj.tls || "").toString().toLowerCase();
      if (tlsVal === "tls" || tlsVal === "1" || tlsVal === "true") {
        tls = true;
      }

      if (!name) {
        name = obj.ps || `${host}:${port}`;
      }

      return {
        raw: uri,
        type: "vmess",
        server: host,
        port,
        cipher,
        uuid,
        alterId,
        tls,
        network,
        path,
        hostHeader,
        name,
      };
    }

    // ========== 分支 2：auth:uuid@host:port / uuid@host:port ==========
    // candidate 可能是：
    //   - auto:UUID@1.2.3.4:443   （Base64 解出来的）
    //   - UUID@1.2.3.4:443        （明文 URL 写法）
    //   - 1.2.3.4:443             （极少见，无 userinfo）
    let userinfo = "";
    let hostPort = candidate;

    const atIdx2 = candidate.lastIndexOf("@");
    if (atIdx2 !== -1) {
      userinfo = candidate.substring(0, atIdx2);
      hostPort = candidate.substring(atIdx2 + 1) || hostPort;
    }

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index) || host;
    }

    // userinfo 可能是：
    //   ""                        → uuid 只能从 query 中拿（几乎不会）
    //   "uuid"                    → 直接是 uuid
    //   "auto:uuid" / "chacha20:uuid" → cipher:uuid
    let cipher = "auto";
    let uuid = "";

    if (userinfo) {
      if (userinfo.includes(":")) {
        const parts = userinfo.split(":", 2);
        if (parts[0]) cipher = parts[0];
        uuid = parts[1] || "";
      } else {
        uuid = userinfo;
      }
    }

    let network = "tcp";
    let path = "/";
    let hostHeader = "";
    let tls = false;
    let alterId = 0;

    // ========== 解析 query：兼容旧参数与新参数 ==========
    if (queryStr) {
      const qs = new URLSearchParams(queryStr);

      // 备注（老写法：remarks）
      const remarks = qs.get("remarks");
      if (remarks) {
        name = decodeNameMaybeTwice(remarks);
      }

      // 加密：encryption / scy
      const enc = qs.get("encryption") || qs.get("scy");
      if (enc) cipher = enc;

      // 传输层类型：type / net
      const netParam = (qs.get("type") || qs.get("net") || "").toLowerCase();

      // VMess 早期机场常用：obfs=http / websocket
      const obfs = (qs.get("obfs") || "").toLowerCase();

      // path
      const pathParam = qs.get("path");
      if (pathParam) {
        try {
          path = decodeURIComponent(pathParam) || "/";
        } catch (_e) {
          path = pathParam || "/";
        }
      }

      // Host / obfsParam 兼容
      const hostParam = qs.get("host") || qs.get("obfsParam");
      if (hostParam) {
        try {
          hostHeader = decodeURIComponent(hostParam);
        } catch (_e) {
          hostHeader = hostParam;
        }
      }

      // TLS 开关：security / tls
      const security = (qs.get("security") || "").toLowerCase();
      const tlsParam = (qs.get("tls") || "").toLowerCase();
      if (security && security !== "none") {
        tls = true;
      } else if (tlsParam === "1" || tlsParam === "true" || tlsParam === "tls") {
        tls = true;
      }

      // 根据参数决定最终 network
      if (netParam) {
        network = netParam;
      } else if (obfs === "http") {
        network = "http";
      } else if (obfs === "websocket") {
        network = "ws";
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      type: "vmess",
      server: host,
      port,
      cipher,
      uuid,
      alterId,
      tls,
      network,
      path,
      hostHeader,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= VLESS 解析：vless:// ================= */

function getVlessShape(n) {
  if (n.network === "ws") return "vless-ws-udp";
  if (n.flow && n.flow.toLowerCase().includes("xtls")) {
    return "vless-xtls-udp";
  }
  return "vless-udp";
}

function parseVless(uri) {
  try {
    if (!uri.toLowerCase().startsWith("vless://")) return null;

    let u = uri.replace(/^vless:\/\//i, "").trim();

    // 提取备注
    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    let mainPart = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      mainPart = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    // mainPart: uuid@host:port
    const atIdx = mainPart.lastIndexOf("@");
    if (atIdx === -1) return null;
    const uuid = mainPart.substring(0, atIdx);
    const hostPort = mainPart.substring(atIdx + 1);

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let network = "tcp";
    let flow = "";
    let sni = "";
    let pbk = "";
    let sid = "";
    let skipCertVerify = false;
    let hostHeader = "";
    let path = "/";
    let tls = false;

    if (queryStr) {
      const qs = new URLSearchParams(queryStr);

      const type = (qs.get("type") || "").toLowerCase();
      if (type) {
        network = type;
      }

      const flowParam = qs.get("flow");
      if (flowParam) {
        flow = flowParam;
      }

      const security = (qs.get("security") || "").toLowerCase();
      if (security === "reality") {
        tls = true;
        const pbkParam = qs.get("pbk");
        if (pbkParam) pbk = pbkParam;
        const sidParam = qs.get("sid");
        if (sidParam) sid = sidParam;
      } else if (security === "tls") {
        tls = true;
      }

      const sniParam = qs.get("sni") || qs.get("peer");
      if (sniParam) {
        try {
          sni = decodeURIComponent(sniParam);
        } catch (_e) {
          sni = sniParam;
        }
      }

      const insecure = (qs.get("allow-insecure") || qs.get("allowInsecure") || "").toLowerCase();
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }

      const hostParam = qs.get("host");
      if (hostParam) {
        try {
          hostHeader = decodeURIComponent(hostParam);
        } catch (_e) {
          hostHeader = hostParam;
        }
      }

      const pathParam = qs.get("path");
      if (pathParam) {
        try {
          path = decodeURIComponent(pathParam) || "/";
        } catch (_e) {
          path = pathParam || "/";
        }
      }
    }

    if (!name) {
      name = host + ":" + port;
    }

    return {
      raw: uri,
      type: "vless",
      server: host,
      port,
      uuid,
      tls,
      skipCertVerify,
      pbk,
      sid,
      sni,
      flow,
      network,
      hostHeader,
      path,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= 通用工具函数 ================= */

function decodeNameMaybeTwice(str) {
  let s = str || "";
  try {
    if (s.includes("%")) s = decodeURIComponent(s);
  } catch (_e) {}
  try {
    if (s.includes("%")) s = decodeURIComponent(s);
  } catch (_e) {}
  return s;
}

function safeBase64Decode(str) {
  if (!str) return "";
  let s = str.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad === 1) return "";
  try {
    const bin = atob(s);
    try {
      return decodeURIComponent(
        Array.prototype.map
          .call(bin, (c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
    } catch (_e) {
      return bin;
    }
  } catch (_e) {
    return "";
  }
}