// functions/api/node-convert.js
//
// 通用节点转换：POST /api/node-convert?client=<clientName>
//
// 支持两种 Shadowsocks 输入：
//  1) ss://BASE64...  （URL 格式）
//  2) shadowsocks=... （Quantumult X 行）
//
// 其它协议（vmess/vless/trojan...）只保留原文，给 V2 订阅使用。

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const rawText = await request.text();
  const text = rawText || "";

  // 1. 拆行，去掉空行和注释
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"));

  if (!lines.length) {
    return new Response("", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 2. 解析为“节点对象数组”
  const nodes = [];
  for (const line of lines) {
    const lower = line.toLowerCase();

    if (lower.startsWith("ss://")) {
      // Shadowsocks URL
      try {
        const n = parseShadowsocksFromSsUrl(line);
        nodes.push(n);
      } catch (_e) {
        nodes.push({ raw: line, scheme: "ss-raw" });
      }
    } else if (lower.startsWith("shadowsocks=")) {
      // Quantumult X Shadowsocks 行
      try {
        const n = parseShadowsocksFromQX(line);
        nodes.push(n);
      } catch (_e) {
        nodes.push({ raw: line, scheme: "ss-raw" });
      }
    } else {
      // 其它协议：记录原文 + scheme
      const scheme = line.split(":", 1)[0].toLowerCase();
      nodes.push({ raw: line, scheme });
    }
  }

  const clashClients = new Set([
    "clash",
    "mihomo",
    "stash",
    "egern",
    "surfboard",
    "loon",
  ]);

  let outText = "";
  let contentType = "text/plain; charset=utf-8";

  if (client === "v2ray") {
    // 通用 V2 订阅（原始节点文本整体 Base64）
    outText = buildV2raySubscription(nodes);
  } else if (clashClients.has(client)) {
    // Clash 系：只用 Shadowsocks 节点生成 YAML
    outText = buildClashConfig(nodes);
    contentType = "text/yaml; charset=utf-8";
  } else if (client === "surge") {
    // Surge：只用 Shadowsocks 节点生成行
    outText = buildSurgeConfig(nodes);
  } else if (client === "quantumultx") {
    // Quantumult X：只用 Shadowsocks 节点生成 shadowsocks=... 行
    outText = buildQuantumultXConfig(nodes);
  } else {
    // 其它客户端（包含 Shadowrocket 等） → 通用 V2 Base64 订阅
    outText = buildV2raySubscription(nodes);
  }

  return new Response(outText, {
    status: 200,
    headers: { "content-type": contentType },
  });
}

/* ================= Base64 & UTF-8 ================= */

function safeBase64Decode(input) {
  try {
    let s = (input || "").trim();
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad === 2) s += "==";
    else if (pad === 3) s += "=";
    else if (pad === 1) s += "===";
    return decodeURIComponent(escape(atob(s)));
  } catch (_e) {
    return "";
  }
}

function utf8ToBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

/* ================= Shadowsocks 解析：ss:// URL ================= */
/**
 * 支持：
 *   ss://BASE64(method:password)@server:port?plugin=...
 *   ss://BASE64(method:password@server:port?plugin=...)
 *
 * 混淆：
 *   plugin=obfs-local;obfs=http|tls;obfs-host=xxx;obfs-uri=/path
 *
 * UDP：
 *   security=1 / udp=1 / udp=true（只解析，不强制输出）
 */
function parseShadowsocksFromSsUrl(uri) {
  let u = uri.replace(/^ss:\/\//i, "");

  // 备注（# 后）
  let name = "";
  const hashIndex = u.indexOf("#");
  if (hashIndex !== -1) {
    name = decodeURIComponent(u.slice(hashIndex + 1));
    u = u.slice(0, hashIndex);
  }

  let userinfo = "";
  let serverPart = "";

  const atIndex = u.indexOf("@");
  if (atIndex !== -1) {
    // BASE64(method:pwd)@server:port?query
    userinfo = u.slice(0, atIndex);
    serverPart = u.slice(atIndex + 1);
  } else {
    // BASE64(method:pwd@server:port?query)
    const decodedAll = safeBase64Decode(u);
    if (!decodedAll || !decodedAll.includes("@")) {
      throw new Error("invalid ss uri (no @ after decoding)");
    }
    const idx = decodedAll.indexOf("@");
    userinfo = decodedAll.slice(0, idx);
    serverPart = decodedAll.slice(idx + 1);
  }

  // userinfo 仍可能是 Base64(method:pwd)
  if (!userinfo.includes(":")) {
    const decodedUser = safeBase64Decode(userinfo);
    if (decodedUser && decodedUser.includes(":")) {
      userinfo = decodedUser;
    }
  }

  const colonIndex = userinfo.indexOf(":");
  if (colonIndex === -1) {
    throw new Error("invalid ss userinfo (no :)");
  }
  const method = userinfo.slice(0, colonIndex); // cipher
  const password = userinfo.slice(colonIndex + 1); // 密码，可包含冒号

  // server:port?query —— 这里用正则抽端口，避免 NaN
  const [hostPortRaw, queryStr = ""] = serverPart.split("?");
  const hostPort = hostPortRaw.trim();

  const m = /:(\d+)$/.exec(hostPort);
  if (!m) {
    throw new Error("invalid ss host/port (no :port)");
  }
  const portStr = m[1];
  const port = parseInt(portStr, 10);
  if (!Number.isFinite(port)) {
    throw new Error("invalid ss port (NaN)");
  }

  const server = hostPort.slice(0, m.index); // ":" 前面部分

  const q = new URLSearchParams(queryStr);

  // plugin=obfs-local;obfs=http|tls;obfs-host=...;obfs-uri=/...
  const pluginRaw = q.get("plugin") || "";
  let plugin = "";
  let pluginMode = ""; // http / tls
  let pluginHost = "";
  let pluginPath = "";

  if (pluginRaw) {
    if (pluginRaw.includes("obfs-local")) {
      plugin = "obfs";

      const mMode = /obfs=([^;]+)/.exec(pluginRaw);
      if (mMode) pluginMode = mMode[1];

      const mHost = /obfs-host=([^;]+)/.exec(pluginRaw);
      if (mHost) pluginHost = decodeURIComponent(mHost[1] || "");

      const mPath = /obfs-uri=([^;]+)/.exec(pluginRaw);
      if (mPath) pluginPath = mPath[1] || "/";
    }
  }

  // UDP 标记（解析出来，用不用另说）
  let udp = false;
  const sec = q.get("security");
  const udpFlag = q.get("udp");
  if (sec === "1" || sec === "true") udp = true;
  if (udpFlag === "1" || udpFlag === "true") udp = true;

  return {
    raw: uri,
    scheme: "ss",

    type: "ss",
    name: name || `${server}:${port}`,
    server,
    port,
    cipher: method,
    password,

    udp,

    plugin,
    pluginMode,
    pluginHost,
    pluginPath,

    obfs: pluginMode,
    obfsHost: pluginHost,
    path: pluginPath || "/",
  };
}

/* ================= Shadowsocks 解析：Quantumult X 行 ================= */
/**
 * 解析形如：
 *
 * shadowsocks=cncgzbgp01.224837439.xyz:14091,
 *   method=chacha20-ietf-poly1305,
 *   password=lE9uL5fR3yR9,
 *   obfs=http,
 *   obfs-host=4aaef245bd.iqiyi.com,
 *   tag=HK - 香港
 */
function parseShadowsocksFromQX(line) {
  const parts = line.split(",");
  if (!parts.length) throw new Error("empty qx shadowsocks");

  const first = parts[0].trim(); // shadowsocks=server:port
  const m = /^shadowsocks=(.+?):(\d+)$/.exec(first);
  if (!m) throw new Error("invalid qx shadowsocks head");
  const server = m[1];
  const port = parseInt(m[2], 10);
  if (!Number.isFinite(port)) throw new Error("invalid qx port");

  let method = "";
  let password = "";
  let obfsMode = "";
  let obfsHost = "";
  let name = "";

  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].trim();
    const idx = seg.indexOf("=");
    if (idx === -1) continue;
    const key = seg.slice(0, idx).trim();
    const value = seg.slice(idx + 1).trim();

    switch (key) {
      case "method":
        method = value;
        break;
      case "password":
        password = value;
        break;
      case "obfs":
        obfsMode = value;
        break;
      case "obfs-host":
        obfsHost = value;
        break;
      case "tag":
        name = value;
        break;
    }
  }

  return {
    raw: line,
    scheme: "ss",

    type: "ss",
    name: name || `${server}:${port}`,
    server,
    port,
    cipher: method,
    password,

    udp: false,

    plugin: obfsMode ? "obfs" : "",
    pluginMode: obfsMode || "",
    pluginHost: obfsHost || "",
    pluginPath: "",

    obfs: obfsMode || "",
    obfsHost: obfsHost || "",
    path: "/",
  };
}

/* ================= V2Ray 订阅（Base64） ================= */

function buildV2raySubscription(nodes) {
  const text = nodes
    .map((n) => (n.raw || "").trim())
    .filter((s) => s)
    .join("\n");

  if (!text) return "";
  return utf8ToBase64(text);
}

/* ================= Clash YAML ================= */

function buildClashConfig(nodes) {
  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const name = n.name || `${n.server}:${n.port}`;

    lines.push(`  - name: "${escapeYaml(name)}"`);
    lines.push("    type: ss");
    lines.push(`    server: "${escapeYaml(n.server)}"`);
    lines.push(`    port: ${n.port}`);
    lines.push(`    cipher: "${escapeYaml(n.cipher)}"`);
    lines.push(`    password: "${escapeYaml(n.password)}"`);

    if (n.plugin === "obfs" && (n.pluginMode === "http" || n.pluginMode === "tls")) {
      lines.push('    plugin: "obfs"');
      lines.push("    plugin-opts:");
      lines.push(`      mode: "${n.pluginMode}"`);
      if (n.pluginHost) {
        lines.push(`      host: "${escapeYaml(n.pluginHost)}"`);
      }
      if (n.pluginPath) {
        lines.push(`      uri: "${escapeYaml(n.pluginPath)}"`);
      }
    }
  }

  if (lines.length === 1) {
    return "proxies: []\n";
  }

  return lines.join("\n") + "\n";
}

function escapeYaml(str) {
  if (!str) return "";
  return String(str).replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

/* ================= Surge ================= */

function buildSurgeConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const name = (n.name || `${n.server}:${n.port}`).replace(/,/g, " ");
    const server = n.server;
    const port = n.port;
    const method = n.cipher;
    const password = n.password;

    let line = `${name}=ss,${server},${port},encrypt-method=${method},password="${password}"`;

    if (n.plugin === "obfs" && n.pluginMode) {
      line += `,obfs=${n.pluginMode}`;
      if (n.pluginHost) {
        line += `,obfs-host=${n.pluginHost}`;
      }
    }

    lines.push(line);
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}

/* ================= Quantumult X ================= */

function buildQuantumultXConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const name = (n.name || `${n.server}:${n.port}`).replace(/,/g, " ");
    const server = n.server;
    const port = n.port;
    const method = n.cipher;
    const password = n.password;

    const parts = [];
    parts.push(`shadowsocks=${server}:${port}`);
    parts.push(`method=${method}`);
    parts.push(`password=${password}`);

    if (n.plugin === "obfs" && n.pluginMode) {
      parts.push(`obfs=${n.pluginMode}`);
      if (n.pluginHost) {
        parts.push(`obfs-host=${n.pluginHost}`);
      }
    }

    parts.push(`tag=${name}`);

    lines.push(parts.join(","));
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}