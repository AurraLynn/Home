// functions/api/sub/Surge.js
//
// 支持输入：
// -  URL 格式：ss://...
// -  URL / Base64 混合格式（一行一个）
// -  Base64 订阅（单条或多条）
//
// 支持输出：
// -  Surge：shadowsocks / UDP
//   例如：
//   HK IEPL 05=ss,gs7ds312f.gdufds.xyz,38550,encrypt-method=chacha20-ietf-poly1305,password="4a24574e-a9a2-48b6-a8e9-66fe08fd1dfb"
//   HK - 香港=ss,cncgzbgp01.224837439.xyz,14091,encrypt-method=chacha20-ietf-poly1305,password="lE9uL5fR3yR9",obfs=http,obfs-host=4aaef245bd.iqiyi.com
//
// 已支持的客户端：
// -  Surge

export async function onRequestPost(context) {
  const { request } = context;
  const raw = (await request.text()) || "";
  let text = raw.trim();

  // ===== 1. 如果整段是 Base64 订阅，尝试整体解码 =====
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

    // 如果不是 ss:// 开头，可能是一行 Base64，尝试解码
    if (!line.startsWith("ss://")) {
      const decodedLine = tryBase64DecodeToString(line);
      if (decodedLine && decodedLine.startsWith("ss://")) {
        line = decodedLine;
      } else {
        continue;
      }
    }

    const node = parseShadowsocksUrl(line);
    if (node) {
      nodes.push(node);
    }
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
    if (!outLines.length) {
      out = "# no shadowsocks nodes\n";
    } else {
      out =
        "# Surge shadowsocks subscription\n" +
        outLines.join("\n") +
        "\n";
    }
  }

  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ========== 工具：Base64 解码（兼容 URL 安全形式） ========== */

function tryBase64DecodeToString(str) {
  if (!str) return "";
  let s = str.replace(/\s+/g, "");

  if (!/^[A-Za-z0-9+/=_-]+$/.test(s)) return "";

  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4 !== 0) {
    s += "=";
  }

  try {
    const decoded = atob(s);
    if (!decoded) return "";
    return decoded;
  } catch (_e) {
    return "";
  }
}

/* ========== 解析 Shadowsocks URL ========== */

function parseShadowsocksUrl(url) {
  try {
    if (!url.startsWith("ss://")) return null;

    let s = url.slice(5); // 去掉 "ss://"

    // 1) 分离 #name（节点名称）
    let name = "";
    const hashIndex = s.indexOf("#");
    if (hashIndex !== -1) {
      name = s.slice(hashIndex + 1);
      s = s.slice(0, hashIndex);
      try {
        name = decodeURIComponent(name);
      } catch (_e) {
        // 保留原样
      }
    }

    // 2) s 现在是 [userinfo@]server:port[?params] 或 整体 Base64
    if (!s.includes("@")) {
      const decoded = tryBase64DecodeToString(s);
      if (decoded && decoded.includes("@")) {
        s = decoded;
      } else {
        return null;
      }
    }

    // 3) 切 userinfo 与 serverPortAndParams（按最后一个 @）
    const atIndex = s.lastIndexOf("@");
    if (atIndex === -1) return null;

    let userinfo = s.slice(0, atIndex);
    let serverPortAndParams = s.slice(atIndex + 1);

    // 4) 解析 userinfo → method:password
    let method = "";
    let password = "";

    // userinfo 可能是 Base64，也可能已经是 method:password
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
    method = userinfo.slice(0, colonIndex);
    password = userinfo.slice(colonIndex + 1);

    // 5) serverPortAndParams → server:port + params
    let query = "";
    const qIndex = serverPortAndParams.indexOf("?");
    if (qIndex !== -1) {
      query = serverPortAndParams.slice(qIndex + 1);
      serverPortAndParams = serverPortAndParams.slice(0, qIndex);
    }

    // server:port（按最后一个 : 分割，避免 IPv6 干扰）
    const lastColon = serverPortAndParams.lastIndexOf(":");
    if (lastColon === -1) return null;

    const server = serverPortAndParams.slice(0, lastColon);
    const portStr = serverPortAndParams.slice(lastColon + 1);
    const port = parseInt(portStr, 10);
    if (!server || !Number.isFinite(port)) return null;

    // 6) 解析 plugin 参数（obfs-local;obfs=http;obfs-host=xxx;obfs-uri=/）
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

          if (key === "obfs") {
            obfsMode = val; // http / tls
          } else if (key === "obfs-host") {
            try {
              obfsHost = decodeURIComponent(val);
            } catch (_e) {
              obfsHost = val;
            }
          }
          // obfs-uri 对 Surge 不需要
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

/* ========== 构造 Surge shadowsocks 行 ========== */

function buildSurgeShadowsocksLine(node) {
  if (!node || node.type !== "ss") return "";

  const server = node.server || "";
  const port = node.port;
  const method = node.method || "";
  const password = node.password || "";
  const tag = node.name || `${server}:${port}`;

  if (!server || !Number.isFinite(port) || !method || !password) {
    return "";
  }

  const parts = [];

  // 名称=ss,server,port
  parts.push(`${escapeComma(tag)}=ss`);
  parts.push(server);
  parts.push(String(port));

  // 加密方式 & 密码（密码按示例包上双引号）
  parts.push(`encrypt-method=${method}`);
  parts.push(`password="${escapeQuote(password)}"`);

  // 混淆：HTTP / TLS
  if (node.obfsMode === "http" || node.obfsMode === "tls") {
    parts.push(`obfs=${node.obfsMode}`);
    if (node.obfsHost) {
      parts.push(`obfs-host=${escapeComma(node.obfsHost)}`);
    }
  }

  // UDP：Surge 默认支持，无需额外参数。
  // 如需强制开启可追加：parts.push("udp-relay=true");

  return parts.join(",");
}

// 处理逗号，避免打乱参数
function escapeComma(str) {
  if (!str) return "";
  return String(str).replace(/,/g, "，");
}

// 处理引号，避免破坏 password="..."
function escapeQuote(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}
