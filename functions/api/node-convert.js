// functions/api/node-convert.js
//
// 通用节点转换：POST /api/node-convert?client=<clientName>
//
// 输入：纯文本，多行节点，可能包含：
//   - ss://...       （URL 格式）
//   - shadowsocks=.. （Quantumult X 行）
//   - 其它协议：vmess:// / vless:// / trojan:// ...
//
// 输出：根据 client 类型生成对应格式，或者回退为通用 V2 Base64 订阅。

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const rawText = await request.text();
  const text = rawText || "";

  // 1. 拆行，去空行和注释
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

  // 2. 解析成“节点对象”
  const nodes = [];
  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    const lower = line.toLowerCase();

    if (lower.startsWith("ss://")) {
      // Shadowsocks URL
      try {
        const n = parseShadowsocks(line);
        nodes.push(n);
      } catch (_e) {
        // 解析失败：至少保留原文，V2 订阅还能用
        nodes.push({ raw: line, scheme: "ss", type: "ss-bad" });
      }
    } else if (lower.startsWith("shadowsocks=")) {
      // Quantumult X Shadowsocks 行
      try {
        const n = parseShadowsocksQX(line);
        nodes.push(n);
      } catch (_e) {
        nodes.push({ raw: line, scheme: "ss", type: "ss-bad" });
      }
    } else {
      // 其它协议直接保留原文，用于 V2 订阅
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
    // 通用 V2 Base64 订阅
    outText = buildV2raySubscription(nodes);
  } else if (clashClients.has(client)) {
    // Clash 系 YAML（只输出 type=ss 的节点）
    outText = buildClashConfig(nodes);
    contentType = "text/yaml; charset=utf-8";
  } else if (client === "surge") {
    // Surge 格式（只输出 SS）
    outText = buildSurgeConfig(nodes);
  } else if (client === "quantumultx") {
    // Quantumult X Shadowsocks 行（只输出 SS）
    outText = buildQuantumultXConfig(nodes);
  } else {
    // 其它客户端（含小火箭） → 通用 V2 Base64 订阅
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
 *   security=1 / udp=1 / udp=true（只解析，输出格式里不强制写）
 */
function parseShadowsocks(uri) {
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

  // userinfo 可能还是 BASE64(method:pwd)
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

  // server:port?query —— 用正则从末尾抽端口，避免 NaN
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

  const server = hostPort.slice(0, m.index); // ":" 前面的部分

  // 用 URLSearchParams 解析 query；注意 ; 也会被当作分隔符
  const q = new URLSearchParams(queryStr);

  // plugin=obfs-local;obfs=http;obfs-host=...;obfs-uri=/...
  const pluginParam = q.get("plugin") || "";
  let plugin = "";
  let pluginMode = ""; // http / tls
  let pluginHost = "";
  let pluginPath = "";

  if (pluginParam && pluginParam.includes("obfs-local")) {
    plugin = "obfs";

    // obfs / obfs-host / obfs-uri 通常会被解析成独立的 query 参数
    pluginMode = q.get("obfs") || "";
    pluginHost = q.get("obfs-host") ? decodeURIComponent(q.get("obfs-host")) : "";
    pluginPath = q.get("obfs-uri") || "";

    // 兼容「全部写在 plugin 里」的旧写法
    if (!pluginMode) {
      const mMode = /obfs=([^;]+)/.exec(pluginParam);
      if (mMode) pluginMode = mMode[1];
    }
    if (!pluginHost) {
      const mHost = /obfs-host=([^;]+)/.exec(pluginParam);
      if (mHost) pluginHost = decodeURIComponent(mHost[1] || "");
    }
    if (!pluginPath) {
      const mPath = /obfs-uri=([^;]+)/.exec(pluginParam);
      if (mPath) pluginPath = mPath[1] || "/";
    }
  }

  // UDP 标记（只解析，不强制输出）
  let udp = false;
  const sec = q.get("security");
  const udpFlag = q.get("udp");
  if (sec === "1" || sec === "true") udp = true;
  if (udpFlag === "1" || udpFlag === "true") udp = true;

  return {
    raw: uri,
    scheme: "ss",
    type: "ss",

    name: name || `${server}:${port}`, // 支持 emoji / 中文
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
function parseShadowsocksQX(line) {
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

/* ================= Clash YAML（只输出 SS 节点） ================= */

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

/* ================= Surge（只输出 SS 节点） ================= */

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

/* ================= Quantumult X（只输出 SS 节点） ================= */

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