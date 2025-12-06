// functions/api/sub/Surge.js
//
// 支持输入：
// - URL 格式（ss://）
// - URL / Base64 混合（逐行）
// - Base64 订阅
//
// 支持输出：
// - Surge：shadowsocks / UDP（含 http / tls 混淆）
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
  if (decodedBulk && decodedBulk.includes("ss://")) {
    text = decodedBulk;
  }

  const lines = text.split(/\r?\n/);
  const nodes = [];

  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith("#")) continue;

    // 单行尝试 Base64
    if (!line.startsWith("ss://")) {
      const decodedLine = tryBase64DecodeToString(line);
      if (decodedLine && decodedLine.startsWith("ss://")) {
        line = decodedLine;
      } else {
        continue;
      }
    }

    const node = parseShadowsocksUrl(line);
    if (node) nodes.push(node);
  }

  let out = "";

  if (!nodes.length) {
    out = "# no shadowsocks nodes\n";
  } else {
    const outLines = [];
    for (const n of nodes) {
      const surgeLine = buildSurgeShadowsocksLine(n);
      if (surgeLine) outLines.push(surgeLine);
    }
    out =
      (outLines.length ? "# Surge shadowsocks\n" + outLines.join("\n") : "# no shadowsocks nodes") +
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

/* 构造 Surge shadowsocks 行：名称=ss,server,port,encrypt-method=...,password="...",obfs=...,obfs-host=... */
function buildSurgeShadowsocksLine(node) {
  if (!node || node.type !== "ss") return "";

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

function escapeComma(str) {
  if (!str) return "";
  return String(str).replace(/,/g, "，");
}

function escapeQuote(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}
