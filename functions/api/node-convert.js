// functions/api/node-convert.js
//
// 通用节点转换：POST /api/node-convert?client=<clientName>
//
// 当前版本策略：
//
// 1. 专门支持 Shadowsocks：
//    - ss:// BASE64(method:password)@server:port?plugin=...
//    - ss:// BASE64(method:password@server:port?plugin=...)
//    - 支持 plugin=obfs-local;obfs=http|tls;obfs-host=...;obfs-uri=/path
//    - 支持 security=1 / udp=1 / udp=true 标记 UDP 开启
// 2. 对 vmess / vless / trojan 等其它协议：不解析，只保留原始行，在 v2ray 订阅里原样输出。
// 3. client 行为：
//    - client=v2ray            → 所有原始行拼在一起做一次 Base64（通用 V2 订阅）
//    - client=clash/mihomo/... → 生成只包含 SS 节点的 Clash YAML（含 http/tls 混淆 & UDP）
//    - client=surge            → 生成 SS 的 Surge 行
//    - client=quantumultx      → 生成 SS 的 Quantumult X 行（不含 obfs-uri / udp-relay）
//    - 其它 client             → 回退到 v2ray Base64 订阅
//
// 不包含任何针对 Shadowrocket 的专用逻辑。

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const rawText = await request.text();
  const text = rawText || "";

  // 先拆行，去掉空行和注释
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

  // 解析为节点对象数组
  const nodes = [];
  for (const line of lines) {
    const lower = line.toLowerCase();
    if (lower.startsWith("ss://")) {
      // Shadowsocks：做结构化解析（含混淆 + UDP）
      try {
        const n = parseShadowsocks(line);
        nodes.push(n);
      } catch (_e) {
        // 单条 ss 解析失败，保留原始文本，至少 v2 订阅还能用
        nodes.push({ raw: line, scheme: "ss-raw" });
      }
    } else {
      // 其它协议：只保留原始文本
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
    // Clash 系：只输出 Shadowsocks 节点的 YAML
    outText = buildClashConfig(nodes);
    contentType = "text/yaml; charset=utf-8";
  } else if (client === "surge") {
    // Surge：输出 SS 行
    outText = buildSurgeConfig(nodes);
  } else if (client === "quantumultx") {
    // Quantumult X：输出 SS 行（不含 obfs-uri / udp-relay）
    outText = buildQuantumultXConfig(nodes);
  } else {
    // 其它客户端：统一回退到 V2 订阅
    outText = buildV2raySubscription(nodes);
  }

  return new Response(outText, {
    status: 200,
    headers: {
      "content-type": contentType,
    },
  });
}

/* ================= 工具：Base64 与 UTF-8 ================= */

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
      throw new Error("invalid ss uri");
    }
    const idx = decodedAll.indexOf("@");
    userinfo = decodedAll.slice(0, idx);
    serverPart = decodedAll.slice(idx + 1);
  }

  // userinfo 仍可能是 BASE64(method:pwd)
  if (!userinfo.includes(":")) {
    const decodedUser = safeBase64Decode(userinfo);
    if (decodedUser && decodedUser.includes(":")) {
      userinfo = decodedUser;
    }
  }

  const colonIndex = userinfo.indexOf(":");
  if (colonIndex === -1) {
    throw new Error("invalid ss userinfo");
  }
  const method = userinfo.slice(0, colonIndex); // cipher
  const password = userinfo.slice(colonIndex + 1); // 密码（可包含冒号）

  const [hostPort, queryStr = ""] = serverPart.split("?");
  const lastColon = hostPort.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error("invalid ss host/port");
  }
  const server = hostPort.slice(0, lastColon);
  const port = Number(hostPort.slice(lastColon + 1));

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
      if (mMode) pluginMode = mMode[1]; // http / tls

      const mHost = /obfs-host=([^;]+)/.exec(pluginRaw);
      if (mHost) pluginHost = decodeURIComponent(mHost[1] || "");

      const mPath = /obfs-uri=([^;]+)/.exec(pluginRaw);
      if (mPath) pluginPath = mPath[1] || "/";
    }
  }

  // UDP 标记
  let udp = false;
  const sec = q.get("security");
  const udpFlag = q.get("udp");
  if (sec === "1" || sec === "true") udp = true;
  if (udpFlag === "1" || udpFlag === "true") udp = true;

  return {
    // 原始行，用于 V2 订阅
    raw: uri,
    scheme: "ss",

    // 结构化字段
    type: "ss",
    name: name || `${server}:${port}`, // 名字可以是 emoji / 特殊字符
    server,
    port,
    cipher: method,
    password,

    udp,

    plugin,
    pluginMode,
    pluginHost,
    pluginPath,

    // 兼容字段
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

/* ================= Clash 系 YAML ================= */

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

    if (n.udp) {
      lines.push("    udp: true");
    }

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
  // 只转义反斜杠和双引号，emoji / 特殊字符原样保留
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

    if (n.udp) {
      line += ",udp-relay=true";
    }

    lines.push(line);
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}

/* ================= Quantumult X ================= */
/**
 * 目标格式（严格对齐你给的）：
 *
 * shadowsocks=server:port,method=...,password=...,obfs=http,obfs-host=...,tag=HK - 香港
 *
 * - 不输出 obfs-uri
 * - 不输出 udp-relay
 */
function buildQuantumultXConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    // 名称里如果有逗号，QX 会乱，这里只替换逗号，保留 emoji / 中文
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

    // ⚠️ 不加 obfs-uri，不加 udp-relay
    parts.push(`tag=${name}`);

    lines.push(parts.join(","));
  }

  if (!lines.length) {
    return "# no shadowsocks nodes\n";
  }

  return lines.join("\n") + "\n";
}