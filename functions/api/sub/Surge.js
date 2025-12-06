// functions/api/sub/Surge.js
//
// 支持输入：
// - URL 格式（ss://、trojan://、vmess://）
// - URL / Base64 混合
// - Base64 订阅
//
// 支持输出：
// - Surge：shadowsocks / UDP（含 http / tls 混淆）
// - Surge：trojan / UDP
// - Surge：vmess / UDP
//
// 已支持的客户端：
// - Surge

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
      decodedBulk.includes("vmess://"))
  ) {
    text = decodedBulk;
  }

  const lines = text.split(/\r?\n/);
  const nodes = [];

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    // 单行尝试 Base64
    if (
      !line.startsWith("ss://") &&
      !line.startsWith("trojan://") &&
      !line.startsWith("vmess://")
    ) {
      const decodedLine = tryBase64DecodeToString(line);
      if (
        decodedLine &&
        (decodedLine.startsWith("ss://") ||
          decodedLine.startsWith("trojan://") ||
          decodedLine.startsWith("vmess://"))
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

/* 解析 Vmess URL（vmess://Base64，Base64 解出 auth:uuid@host:port） */
function parseVmessUrl(url) {
  try {
    if (!url.startsWith("vmess://")) return null;

    let s = url.slice("vmess://".length);

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

    // s 是 Base64：auto:uuid@host:port 或 uuid@host:port
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
    if (query) {
      const params = new URLSearchParams(query);
      const tlsParam = params.get("tls") || params.get("security");
      if (
        tlsParam === "1" ||
        tlsParam === "true" ||
        tlsParam === "tls"
      ) {
        tls = true;
      }
    }

    return {
      type: "vmess",
      name: name || `${server}:${port}`,
      server,
      port,
      uuid,
      tls,
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
  return "";
}

/* 构造 Surge shadowsocks 行 */
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

/* 构造 Surge trojan 行 */
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

/* 构造 Surge vmess 行 */
function buildSurgeVmessLine(node) {
  const server = node.server || "";
  const port = node.port;
  const uuid = node.uuid || "";
  const tag = node.name || `${server}:${port}`;
  const tls = !!node.tls;

  if (!server || !Number.isFinite(port) || !uuid) return "";

  const parts = [];

  parts.push(`${escapeComma(tag)}=vmess`);
  parts.push(server);
  parts.push(String(port));
  parts.push(`username=${escapeQuote(uuid)}`);
  parts.push("vmess-aead=true");
  parts.push(`tls=${tls ? "true" : "false"}`);

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
