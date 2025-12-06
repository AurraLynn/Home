// functions/api/sub/Surge.js
//
// 支持类型输入：
// - URL 格式
// - URL / Base64 混合
// - Base64 单条 / 多条
//
// 支持协议输出（仅支持白名单列表）：
// - Surge：
//      - Shadowsocks / UDP
//      - Shadowsocks / HTTP / UDP
//      - Trojan / UDP
//      - VMESS / UDP
//      - VMESS / Websocket / UDP
//      - Hysteria2 / UDP
//
// client 行为：
// -  只处理 Surge，供 /api/sub/Converter 调用
// -  不在白名单里的协议 / 传输方式一律丢弃，不下发给客户端

export async function onRequestPost(context) {
  const { request } = context;

  const rawText = await request.text();
  const text = (rawText || "").trim();
  if (!text) {
    return new Response("# empty input\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const nodes = parseMixedInputToNodes(text);
  let out = "";

  if (!nodes.length) {
    out = "# no surge nodes\n";
  } else {
    const outLines = [];
    for (const n of nodes) {
      const surgeLine = buildSurgeLine(n);
      if (surgeLine) outLines.push(surgeLine);
    }
    out =
      (outLines.length ? "# Surge nodes\n" + outLines.join("\n") : "# no surge nodes") +
      "\n";
  }

  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// ========== 通用解析：把混合输入拆成一行一行 URL / Base64 ==========

function parseMixedInputToNodes(text) {
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => !!l && !l.startsWith("#") && !l.startsWith("//"));

  const nodes = [];

  for (const lineRaw of lines) {
    let line = lineRaw.trim();

    // Base64 纯订阅整段
    if (!line.includes("://") && /^[A-Za-z0-9+/=]+$/.test(line)) {
      const decoded = safeBase64Decode(line);
      if (!decoded) continue;

      const subLines = decoded
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => !!l && !l.startsWith("#") && !l.startsWith("//"));

      for (const sub of subLines) {
        const n = parseSingleUriToNode(sub);
        if (n) nodes.push(n);
      }
      continue;
    }

    const n = parseSingleUriToNode(line);
    if (n) nodes.push(n);
  }

  return nodes;
}

function parseSingleUriToNode(uri) {
  if (!uri) return null;
  const u = uri.trim();

  if (u.startsWith("ss://")) return parseShadowsocksUrl(u);
  if (u.startsWith("trojan://")) return parseTrojanUrl(u);
  if (u.startsWith("vmess://")) return parseVmessUrl(u);
  if (u.startsWith("hysteria2://")) return parseHysteria2Url(u);

  return null;
}

function safeBase64Decode(s) {
  if (!s) return "";
  let b64 = s.trim();
  b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4;
  if (pad === 2) b64 += "==";
  else if (pad === 3) b64 += "=";
  try {
    const decoded = atob(b64);
    if (!decoded) return "";
    return decoded;
  } catch (_e) {
    return "";
  }
}

/* 解析 Shadowsocks URL */
function parseShadowsocksUrl(url) {
  try {
    if (!url.startsWith("ss://")) return null;

    let s = url.slice(5);

    // 名称
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = decodeURIComponentSafe(s.slice(hashIndex + 1));
      s = s.slice(0, hashIndex);
    }

    // query
    let main = s;
    let queryStr = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      main = s.slice(0, qIndex);
      queryStr = s.slice(qIndex + 1);
    }

    let userinfoHostPort = "";
    const decodedMain = safeBase64Decode(main);
    if (decodedMain && decodedMain.includes("@")) {
      userinfoHostPort = decodedMain;
    } else {
      userinfoHostPort = main;
    }

    const atIndex = userinfoHostPort.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = userinfoHostPort.slice(0, atIndex);
    const serverPart = userinfoHostPort.slice(atIndex + 1);

    let method = "";
    let password = "";

    if (userinfo.includes(":")) {
      const idx = userinfo.indexOf(":");
      method = userinfo.slice(0, idx);
      password = userinfo.slice(idx + 1);
    }

    let hostPortRaw = serverPart;
    if (!queryStr) {
      const q2 = serverPart.indexOf("?");
      if (q2 !== -1) {
        hostPortRaw = serverPart.slice(0, q2);
        queryStr = serverPart.slice(q2 + 1);
      }
    }

    let host = hostPortRaw;
    let port = 8388;
    const m = /:(\d+)$/.exec(hostPortRaw);
    if (m) {
      port = parseInt(m[1], 10) || 8388;
      host = hostPortRaw.slice(0, m.index);
    }

    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const q = new URLSearchParams(queryStr);
      const pluginParam = q.get("plugin") || "";
      if (pluginParam && pluginParam.includes("obfs-local")) {
        plugin = "obfs";

        pluginMode = q.get("obfs") || "";
        pluginHost = q.get("obfs-host")
          ? decodeURIComponentSafe(q.get("obfs-host"))
          : "";

        if (!pluginMode) {
          const mm = /obfs=([^;]+)/.exec(pluginParam);
          if (mm) pluginMode = mm[1];
        }
        if (!pluginHost) {
          const mh = /obfs-host=([^;]+)/.exec(pluginParam);
          if (mh) pluginHost = decodeURIComponentSafe(mh[1] || "");
        }
      }
    }

    if (!name) name = `${host}:${port}`;

    return {
      type: "ss",
      name,
      server: host,
      port,
      method,
      password,
      plugin,
      pluginMode,
      pluginHost,
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 Trojan URL */
function parseTrojanUrl(url) {
  try {
    if (!url.startsWith("trojan://")) return null;

    let s = url.slice(9);

    // name
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = decodeURIComponentSafe(s.slice(hashIndex + 1));
      s = s.slice(0, hashIndex);
    }

    // query
    let main = s;
    let queryStr = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      main = s.slice(0, qIndex);
      queryStr = s.slice(qIndex + 1);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const passwordPart = main.slice(0, atIndex);
    const serverPart = main.slice(atIndex + 1);

    const password = decodeURIComponentSafe(passwordPart);

    let host = serverPart;
    let port = 443;
    const m = /:(\d+)$/.exec(serverPart);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = serverPart.slice(0, m.index);
    }

    let sni = "";
    let skipCertVerify = false;

    if (queryStr) {
      const q = new URLSearchParams(queryStr);
      const peer = q.get("peer") || q.get("sni") || "";
      if (peer) sni = peer;

      const insecure = q.get("allowInsecure") || "";
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }

      const r =
        q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }
    }

    if (!name) name = `${host}:${port}`;

    return {
      type: "trojan",
      name,
      server: host,
      port,
      password,
      sni,
      skipCertVerify,
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 VMESS URL（UDP / WS / HTTP） */
function parseVmessUrl(url) {
  try {
    if (!url.startsWith("vmess://")) return null;

    let s = url.slice(8);

    // name
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = decodeURIComponentSafe(s.slice(hashIndex + 1));
      s = s.slice(0, hashIndex);
    }

    // query
    let main = s;
    let queryStr = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      main = s.slice(0, qIndex);
      queryStr = s.slice(qIndex + 1);
    }

    let decoded = safeBase64Decode(main);
    let userinfoHostPort = "";

    if (decoded && decoded.includes("@") && decoded.includes(":")) {
      userinfoHostPort = decoded;
    } else {
      userinfoHostPort = main;
    }

    const atIndex = userinfoHostPort.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = userinfoHostPort.slice(0, atIndex);
    const hostPort = userinfoHostPort.slice(atIndex + 1);

    let uuid = "";
    if (userinfo.includes(":")) {
      const parts = userinfo.split(":");
      uuid = parts[parts.length - 1] || "";
    } else {
      uuid = userinfo;
    }

    let host = hostPort;
    let port = 443;
    const m = /:(\d+)$/.exec(hostPort);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPort.slice(0, m.index);
    }

    let obfs = "";
    let obfsHost = "";
    let obfsUri = "/";
    let tls = "";

    if (queryStr) {
      const q = new URLSearchParams(queryStr);

      const obfsType = q.get("obfs") || q.get("network") || "";
      const hostFrom = q.get("obfsParam") || q.get("host") || "";
      const path = q.get("path") || q.get("obfsUri") || "/";

      if (obfsType === "websocket" || obfsType === "ws") {
        obfs = "ws";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      } else if (obfsType === "http") {
        obfs = "http";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      }

      if (q.get("tls") === "1" || q.get("security") === "tls") {
        tls = "tls";
      }

      const r =
        q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }
    }

    if (!name) name = `${host}:${port}`;

    return {
      type: "vmess",
      name,
      server: host,
      port,
      uuid,
      obfs,
      obfsHost,
      obfsUri,
      tls,
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 Hysteria2 URL */
function parseHysteria2Url(url) {
  try {
    if (!url.startsWith("hysteria2://")) return null;

    let s = url.slice("hysteria2://".length);

    // name
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = decodeURIComponentSafe(s.slice(hashIndex + 1));
      s = s.slice(0, hashIndex);
    }

    // query
    let main = s;
    let queryStr = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      main = s.slice(0, qIndex);
      queryStr = s.slice(qIndex + 1);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const passwordPart = main.slice(0, atIndex);
    const serverPart = main.slice(atIndex + 1);

    const password = decodeURIComponentSafe(passwordPart);

    let host = serverPart;
    let port = 443;
    const m = /:(\d+)$/.exec(serverPart);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = serverPart.slice(0, m.index);
    }

    let sni = "";
    let portHopping = "";
    let skipCertVerify = false;

    if (queryStr) {
      const q = new URLSearchParams(queryStr);

      const peer = q.get("peer") || q.get("sni") || "";
      if (peer) sni = peer;

      const mport = q.get("mport") || q.get("port-hopping") || "";
      if (mport) portHopping = mport;

      const insecure = q.get("insecure") || "";
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }

      const r =
        q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }
    }

    if (!name) name = `${host}:${port}`;

    return {
      type: "hysteria2",
      name,
      server: host,
      port,
      password,
      sni,
      portHopping,
      skipCertVerify,
    };
  } catch (_e) {
    return null;
  }
}

function decodeURIComponentSafe(s) {
  if (!s) return "";
  try {
    return decodeURIComponent(s);
  } catch (_e) {
    return s;
  }
}

// ========== Surge 白名单：仅下发以下协议 / 传输组合 ==========
//
// 形态 key 约定：
// - ss-udp
// - ss-http-udp
// - trojan-udp
// - vmess-udp
// - vmess-ws-udp
// - hysteria2-udp
const SURGE_ALLOWED_SHAPES = new Set([
  "ss-udp",
  "ss-http-udp",
  "trojan-udp",
  "vmess-udp",
  "vmess-ws-udp",
  "hysteria2-udp",
]);

function getSurgeShape(n) {
  if (!n || !n.type) return "";

  switch (n.type) {
    case "ss": {
      if (n.plugin === "obfs" && (n.pluginMode || "").toLowerCase() === "http") {
        return "ss-http-udp";
      }
      return "ss-udp";
    }
    case "trojan":
      return "trojan-udp";
    case "vmess": {
      const obfs = (n.obfs || "").toLowerCase();
      if (!obfs || obfs === "tcp") return "vmess-udp";
      if (obfs === "ws" || obfs === "websocket") return "vmess-ws-udp";
      return "";
    }
    case "hysteria2":
      return "hysteria2-udp";
    default:
      return "";
  }
}

// ========== Surge 输出构建 ==========

function buildSurgeLine(node) {
  if (!node || !node.type) return "";

  const shape = getSurgeShape(node);
  if (!shape || !SURGE_ALLOWED_SHAPES.has(shape)) {
    return "";
  }

  if (node.type === "ss") return buildSurgeShadowsocksLine(node);
  if (node.type === "trojan") return buildSurgeTrojanLine(node);
  if (node.type === "vmess") return buildSurgeVmessLine(node);
  if (node.type === "hysteria2") return buildSurgeHysteria2Line(node);
  return "";
}

/* shadowsocks */
function buildSurgeShadowsocksLine(node) {
  const server = node.server || "";
  const port = node.port;
  const method = node.method || "";
  const password = node.password || "";
  const tag = node.name || `${server}:${port}`;

  if (!server || !Number.isFinite(port) || !method || !password) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=ss`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`encrypt-method=${method}`);
  parts.push(`password="${escapeQuote(password)}"`);

  if (node.plugin === "obfs" && node.pluginMode === "http") {
    parts.push("obfs=http");
    if (node.pluginHost) {
      parts.push(`obfs-host=${escapeComma(node.pluginHost)}`);
    }
  }

  return parts.join(",");
}

/* trojan */
function buildSurgeTrojanLine(node) {
  const server = node.server || "";
  const port = node.port;
  const password = node.password || "";
  const tag = node.name || `${server}:${port}`;
  const sni = node.sni || "";
  const skipCertVerify = !!node.skipCertVerify;

  if (!server || !Number.isFinite(port) || !password) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=trojan`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`password="${escapeQuote(password)}"`);
  parts.push("tls=true");
  if (sni) {
    parts.push(`sni=${escapeComma(sni)}`);
  }
  if (skipCertVerify) {
    parts.push("skip-cert-verify=true");
  }

  return parts.join(",");
}

/* vmess（含 websocket，跳过 http） */
function buildSurgeVmessLine(node) {
  const server = node.server || "";
  const port = node.port;
  const uuid = node.uuid || "";
  const tag = node.name || `${server}:${port}`;
  const tls = !!node.tls;
  const ws = node.obfs === "ws";
  const wsPath = node.obfsUri || "/";
  const wsHost = node.obfsHost || "";

  if (!server || !Number.isFinite(port) || !uuid) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=vmess`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`username=${uuid}`);
  parts.push("vmess-aead=true");
  parts.push(`tls=${tls ? "true" : "false"}`);

  if (ws) {
    parts.push("ws=true");
    parts.push(`ws-path=${wsPath || "/"}`);
    if (wsHost) {
      parts.push(`ws-headers=Host:"${escapeQuote(wsHost)}"`);
    }
  }

  return parts.join(",");
}

/* hysteria2 */
function buildSurgeHysteria2Line(node) {
  const server = node.server || "";
  const port = node.port;
  const password = node.password || "";
  const tag = node.name || `${server}:${port}`;
  const sni = node.sni || "";
  const portHopping = node.portHopping || "";
  const skipCertVerify = !!node.skipCertVerify;

  if (!server || !Number.isFinite(port) || !password) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=hysteria2`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`password="${escapeQuote(password)}"`);

  if (portHopping) {
    parts.push(`port-hopping="${escapeQuote(portHopping)}"`);
  }
  if (sni) {
    parts.push(`sni=${escapeComma(sni)}`);
  }
  if (skipCertVerify) {
    parts.push("skip-cert-verify=true");
  }

  // 你示例里固定 tfo=false
  parts.push("tfo=false");

  return parts.join(",");
}

function escapeComma(str) {
  if (!str) return "";
  return String(str).replace(/,/g, "，");
}

function escapeQuote(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}