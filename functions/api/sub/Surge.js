// functions/api/sub/Surge.js
//
// 支持类型输入：
// - URL 格式
// - URL / Base64 混合
// - Base64 单条 / 多条
//
// 支持协议输出：
// - Surge：
//      - Shadowsocks / UDP
//      - Shadowsocks / HTTP / UDP
//      - Trojan / UDP
//      - VMESS / UDP
//      - VMESS / Websocket / UDP
//      - Hysteria2 / UDP
//

export async function onRequestPost(context) {
  const { request } = context;
  const raw = (await request.text()) || "";
  let text = raw.trim();

  // 整段尝试 Base64 解码
  const compact = text.replace(/\s+/g, "");
  const decodedBulk = tryBase64DecodeToString(compact);
  if (
    decodedBulk &&
    (decodedBulk.includes("ss://") ||
      decodedBulk.includes("trojan://") ||
      decodedBulk.includes("vmess://") ||
      decodedBulk.includes("hysteria2://"))
  ) {
    text = decodedBulk;
  }

  const lines = text.split(/\r?\n/);
  const nodes = [];

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    // 单行 Base64
    if (
      !line.startsWith("ss://") &&
      !line.startsWith("trojan://") &&
      !line.startsWith("vmess://") &&
      !line.startsWith("hysteria2://")
    ) {
      const decodedLine = tryBase64DecodeToString(line);
      if (
        decodedLine &&
        (decodedLine.startsWith("ss://") ||
          decodedLine.startsWith("trojan://") ||
          decodedLine.startsWith("vmess://") ||
          decodedLine.startsWith("hysteria2://"))
      ) {
        line = decodedLine;
      } else {
        continue;
      }
    }

    let node = null;
    if (line.startsWith("ss://")) {
      node = parseShadowsocksUrl(line);
    } else if (line.startsWith("trojan://")) {
      node = parseTrojanUrl(line);
    } else if (line.startsWith("vmess://")) {
      node = parseVmessUrl(line);
    } else if (line.startsWith("hysteria2://")) {
      node = parseHysteria2Url(line);
    }

    if (node) nodes.push(node);
  }

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

/* Base64 解码（兼容 URL 安全形式） */
function tryBase64DecodeToString(str) {
  if (!str) return "";
  let s = str.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return "";
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) s += "=";
  try {
    const decoded = atob(s);
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
      name = s.slice(hashIndex + 1);
      s = s.slice(0, hashIndex);
      try {
        name = decodeURIComponent(name);
      } catch (_e) {}
    }

    // 主体或整体 Base64
    if (!s.includes("@")) {
      const decoded = tryBase64DecodeToString(s);
      if (decoded && decoded.includes("@")) {
        s = decoded;
      } else {
        return null;
      }
    }

    // userinfo 与 server:port
    const atIndex = s.lastIndexOf("@");
    if (atIndex === -1) return null;

    let userinfo = s.slice(0, atIndex);
    let serverPortAndParams = s.slice(atIndex + 1);

    // userinfo → method:password
    const decodedUserinfo = tryBase64DecodeToString(userinfo);
    if (decodedUserinfo && decodedUserinfo.includes(":")) {
      userinfo = decodedUserinfo;
    } else {
      try {
        userinfo = decodeURIComponent(userinfo);
      } catch (_e) {}
    }

    const colonIndex = userinfo.indexOf(":");
    if (colonIndex === -1) return null;
    const method = userinfo.slice(0, colonIndex);
    const password = userinfo.slice(colonIndex + 1);

    // server:port[?params]
    let query = "";
    const qIndex = serverPortAndParams.indexOf("?");
    if (qIndex !== -1) {
      query = serverPortAndParams.slice(qIndex + 1);
      serverPortAndParams = serverPortAndParams.slice(0, qIndex);
    }

    const lastColon = serverPortAndParams.lastIndexOf(":");
    if (lastColon === -1) return null;

    const server = serverPortAndParams.slice(0, lastColon);
    const portStr = serverPortAndParams.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!server || !Number.isFinite(port)) return null;

    // plugin 混淆
    let obfsMode = "";
    let obfsHost = "";

    if (query) {
      const params = new URLSearchParams(query);
      const plugin = params.get("plugin");
      if (plugin) {
        const parts = plugin.split(";");
        for (const part of parts) {
          const [k, v] = part.split("=");
          const key = (k || "").trim();
          const val = (v || "").trim();
          if (!key) continue;
          if (key === "obfs") obfsMode = val;
          if (key === "obfs-host") {
            try {
              obfsHost = decodeURIComponent(val);
            } catch (_e) {
              obfsHost = val;
            }
          }
        }
      }
    }

    return {
      type: "ss",
      name: name || `${server}:${port}`,
      server,
      port,
      method,
      password,
      obfsMode, // http / tls / ""
      obfsHost, // 可能为空
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 Trojan URL */
function parseTrojanUrl(url) {
  try {
    if (!url.startsWith("trojan://")) return null;

    let s = url.slice("trojan://".length);

    // 名称
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = s.slice(hashIndex + 1);
      s = s.slice(0, hashIndex);
      try {
        name = decodeURIComponent(name);
      } catch (_e) {}
    }

    // 查询参数
    let query = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      query = s.slice(qIndex + 1);
      s = s.slice(0, qIndex);
    }

    // password@server:port
    const atIndex = s.lastIndexOf("@");
    if (atIndex === -1) return null;

    const password = s.slice(0, atIndex);
    const hostPort = s.slice(atIndex + 1);

    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) return null;

    const server = hostPort.slice(0, lastColon);
    const portStr = hostPort.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!server || !Number.isFinite(port)) return null;

    let sni = "";
    let skipCertVerify = false;

    if (query) {
      const params = new URLSearchParams(query);
      const peer = params.get("peer");
      const sniParam = params.get("sni");
      const hostParam = params.get("host");
      sni = peer || sniParam || hostParam || server;

      const allowInsecure =
        params.get("allowInsecure") ||
        params.get("insecure") ||
        params.get("allow_insecure");
      if (allowInsecure === "1" || allowInsecure === "true") {
        skipCertVerify = true;
      }
    } else {
      sni = server;
    }

    return {
      type: "trojan",
      name: name || `${server}:${port}`,
      server,
      port,
      password,
      sni,
      skipCertVerify,
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 Vmess URL（vmess://Base64 + ?remarks=） */
function parseVmessUrl(url) {
  try {
    if (!url.startsWith("vmess://")) return null;

    let s = url.slice("vmess://".length);

    // # 名称（备用）
    let nameFromHash = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      nameFromHash = s.slice(hashIndex + 1);
      s = s.slice(0, hashIndex);
      try {
        nameFromHash = decodeURIComponent(nameFromHash);
      } catch (_e) {}
    }

    // ? 查询参数
    let query = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      query = s.slice(qIndex + 1);
      s = s.slice(0, qIndex);
    }

    // Base64: auto:uuid@host:port 或 uuid@host:port
    const decoded = tryBase64DecodeToString(s);
    if (!decoded) return null;

    const atIndex = decoded.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = decoded.slice(0, atIndex);
    const hostPort = decoded.slice(atIndex + 1);

    let uuid = "";
    const uiParts = userinfo.split(":");
    if (uiParts.length === 1) {
      uuid = uiParts[0];
    } else {
      uuid = uiParts[uiParts.length - 1];
    }

    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) return null;

    const server = hostPort.slice(0, lastColon);
    const portStr = hostPort.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!server || !Number.isFinite(port)) return null;

    let tls = false;
    let ws = false;
    let wsPath = "";
    let wsHost = "";
    let displayName = nameFromHash;
    let transport = "tcp"; // tcp / ws / http

    if (query) {
      const params = new URLSearchParams(query);

      // 名称优先用 remarks
      const remarks = params.get("remarks");
      if (remarks) {
        try {
          displayName = decodeURIComponent(remarks);
        } catch (_e) {
          displayName = remarks;
        }
      }

      // tls / security
      const tlsParam = params.get("tls") || params.get("security");
      if (tlsParam === "1" || tlsParam === "true" || tlsParam === "tls") {
        tls = true;
      }

      // 传输：ws / http
      const obfs = params.get("obfs") || params.get("network");
      if (obfs === "websocket" || obfs === "ws") {
        transport = "ws";
        ws = true;
        wsPath = params.get("path") || "/";
        wsHost = params.get("obfsParam") || params.get("host") || "";
      } else if (obfs === "http") {
        // vmess/http：标记为 http，Surge 不支持，后面直接跳过
        transport = "http";
      }
    }

    return {
      type: "vmess",
      name: displayName || `${server}:${port}`,
      server,
      port,
      uuid,
      tls,
      ws,
      wsPath,
      wsHost,
      transport, // tcp / ws / http
    };
  } catch (_e) {
    return null;
  }
}

/* 解析 Hysteria2 URL（hysteria2://password@host:port?...） */
function parseHysteria2Url(url) {
  try {
    if (!url.startsWith("hysteria2://")) return null;

    let s = url.slice("hysteria2://".length);

    // 名称
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = s.slice(hashIndex + 1);
      s = s.slice(0, hashIndex);
      try {
        name = decodeURIComponent(name);
      } catch (_e) {}
    }

    // 查询参数
    let query = "";
    const qIndex = s.indexOf("?");
    if (qIndex !== -1) {
      query = s.slice(qIndex + 1);
      s = s.slice(0, qIndex);
    }

    // password@server:port
    const atIndex = s.lastIndexOf("@");
    if (atIndex === -1) return null;

    const password = s.slice(0, atIndex);
    const hostPort = s.slice(atIndex + 1);

    const lastColon = hostPort.lastIndexOf(":");
    if (lastColon === -1) return null;

    const server = hostPort.slice(0, lastColon);
    const portStr = hostPort.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!server || !Number.isFinite(port)) return null;

    let sni = server;
    let portHopping = "";
    let skipCertVerify = false;

    if (query) {
      const params = new URLSearchParams(query);

      const peer = params.get("peer");
      if (peer) sni = peer;

      const mport = params.get("mport") || params.get("mport-range");
      if (mport) portHopping = mport;

      const insecure = params.get("insecure");
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }
    }

    return {
      type: "hysteria2",
      name: name || `${server}:${port}`,
      server,
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

/* 根据节点类型构造 Surge 行 */
function buildSurgeLine(node) {
  if (!node || !node.type) return "";
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

  if (node.obfsMode === "http" || node.obfsMode === "tls") {
    parts.push(`obfs=${node.obfsMode}`);
    if (node.obfsHost) {
      parts.push(`obfs-host=${escapeComma(node.obfsHost)}`);
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
  const sni = node.sni || server;
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
  const ws = !!node.ws;
  const wsPath = node.wsPath || "/";
  const wsHost = node.wsHost || "";
  const transport = node.transport || "tcp";

  // vmess/http：Surge 不支持，直接跳过
  if (transport === "http") return "";

  if (!server || !Number.isFinite(port) || !uuid) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=vmess`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`username=${escapeQuote(uuid)}`);
  parts.push(`tls=${tls ? "true" : "false"}`);
  parts.push("vmess-aead=true");

  if (ws) {
    parts.push("ws=true");
    parts.push(`ws-path=${wsPath}`);
    if (wsHost) {
      parts.push(`ws-headers=Host:"${escapeQuote(wsHost)}"`);
    }
  }

  return parts.join(",");
}

/* hysteria2（hy2） */
function buildSurgeHysteria2Line(node) {
  const server = node.server || "";
  const port = node.port;
  const password = node.password || "";
  const tag = node.name || `${server}:${port}`;
  const sni = node.sni || server;
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