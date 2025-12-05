// functions/api/node-convert.js
//
// 通用节点转换：POST /api/node-convert?client=<clientName>
//
// 设计目标：
// 1. 专门解析 Shadowsocks：
//    - ss://BASE64(method:password)@server:port?plugin=...
//    - ss://BASE64(method:password@server:port?plugin=...)
//    - 支持 plugin=obfs-local;obfs=http|tls;obfs-host=...;obfs-uri=/path
//    - 支持 security=1 / udp=1 / udp=true（只解析，不一定输出）
// 2. vmess / vless / trojan 等其它协议：不做结构化解析，只在 v2ray 订阅中原样输出。
// 3. client 行为：
//    - client=v2ray
//         → 通用 V2 订阅（所有原始节点文本拼成多行，然后整体 Base64）
//    - client=clash / mihomo / stash / egern / surfboard / loon
//         → 生成只包含 Shadowsocks 节点的 Clash YAML（含 http/tls 混淆）
//    - client=surge
//         → 生成 Shadowsocks 的 Surge 行（含 http/tls 混淆）
//    - client=quantumultx
//         → 生成 Shadowsocks 的 Quantumult X 行：
//            shadowsocks=server:port,method=...,password=...,obfs=http,obfs-host=...,tag=名字
//         → 不输出 obfs-uri / udp-relay
//    - 其它 client（包括小火箭）
//         → 回退到 v2ray Base64 订阅（原始 ss:// / vmess:// 不动，让客户端自己解析）
//
// 节点名称可以是 emoji、中文及各种特殊字符，不会报错。

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
      try {
        const n = parseShadowsocks(line);
        nodes.push(n);
      } catch (_e) {
        // 某条 ss 解析失败，保留原文，至少 V2 订阅还能用
        nodes.push({ raw: line, scheme: "ss-raw" });
      }
    } else {
      // 其它协议：只记录原文和 scheme
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
    // 通用 V2 订阅：原始节点文本 → Base64
    outText = buildV2raySubscription(nodes);
  } else if (clashClients.has(client)) {
    // Clash 系：输出 Shadowsocks 节点 YAML
    outText = buildClashConfig(nodes);
    contentType = "text/yaml; charset=utf-8";
  } else if (client === "surge") {
    // Surge 格式
    outText = buildSurgeConfig(nodes);
  } else if (client === "quantumultx") {
    // Quantumult X Shadowsocks 行
    outText = buildQuantumultXConfig(nodes);
  } else {
    // 其他客户端（包含小火箭等）：统一使用 V2 Base64 订阅
    outText = buildV2raySubscription(nodes);
  }

  return new Response(outText, {
    status: 200,
    headers: {
      "content-type": contentType,
    },
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

/* ================= Shadowsocks 解析 ================= */
/**
 * 支持：
 *   ss://BASE64(method:password)@server:port?plugin=...
 *   ss://BASE64(method:password@server:port?plugin=...)
 *
 * 混淆：
 *   plugin=obfs-local;obfs=http|tls;obfs-host=xxx;obfs-uri=/path
 *
 * UDP：
 *   security=1 / udp=1 / udp=true（解析出来存储，但默认不在生成格式中输出）
 */
function parseShadowsocks(uri) {
  let u = uri.replace(/^ss:\/\//i, "");

  // 1. 处理备注（# 后的部分）
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
    // 形式：BASE64(method:pwd)@server:port?query
    userinfo = u.slice(0, atIndex);
    serverPart = u.slice(atIndex + 1);
  } else {
    // 形式：BASE64(method:pwd@server:port?query)
    const decodedAll = safeBase64Decode(u);
    if (!decodedAll || !decodedAll.includes("@")) {
      throw new Error("invalid ss uri (no @ after decoding)");
    }
    const idx = decodedAll.indexOf("@");
    userinfo = decodedAll.slice(0, idx);
    serverPart = decodedAll.slice(idx + 1);
  }

  // userinfo 可能还是 Base64（method:pwd）
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

  // 2. 解析 server:port?query —— 这里是关键，修掉 NaN
  const [hostPortRaw, queryStr = ""] = serverPart.split("?");
  const hostPort = hostPortRaw.trim();

  // 用正则从结尾提取端口，只接受纯数字：  something:12345
  const m = /:(\d+)$/.exec(hostPort);
  if (!m) {
    throw new Error("invalid ss host/port (no :port)");
  }

  const portStr = m[1];
  const port = parseInt(portStr, 10);
  if (!Number.isFinite(port)) {
    throw new Error("invalid ss port (NaN)");
  }

  const server = hostPort.slice(0, m.index); // m.index 是 ":" 的位置

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

  // UDP 标记（目前只解析，不强制在输出格式中带出来）
  let udp = false;
  const sec = q.get("security");
  const udpFlag = q.get("udp");
  if (sec === "1" || sec === "true") udp = true;
  if (udpFlag === "1" || udpFlag === "true") udp = true;

  return {
    raw: uri,
    scheme: "ss",

    type: "ss",
    name: name || `${server}:${port}`, // 可以是 emoji + 特殊字符
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

    // 这里暂时不输出 udp: true，避免某些客户端解析异常

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

    // 不再输出 udp-relay=true，避免某些客户端解析问题

    lines.push(line);
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}

/* ================= Quantumult X ================= */
/**
 * 目标格式（严格对齐你给的那条）：
 *
 * shadowsocks=cncgzbgp01.224837439.xyz:14091,
 *   method=chacha20-ietf-poly1305,
 *   password=lE9uL5fR3yR9,
 *   obfs=http,
 *   obfs-host=4aaef245bd.iqiyi.com,
 *   tag=HK - 香港
 *
 * - 不输出 obfs-uri
 * - 不输出 udp-relay
 */
function buildQuantumultXConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    // 名称里如果有逗号，QX 容易乱，这里替换逗号为空格，保留 emoji 和中文
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

    // 不带 obfs-uri / udp-relay
    parts.push(`tag=${name}`);

    lines.push(parts.join(","));
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}