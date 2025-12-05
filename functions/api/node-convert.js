// functions/api/node-convert.js
//
// 通用节点转换：POST /api/node-convert?client=<clientName>
//
// 支持输入：
//   - ss://...       （URL 格式，支持 obfs-local http/tls 混淆）
//   - shadowsocks=.. （Quantumult X shadowsocks 行）
//   - vless://...    （支持你给的 Base64 打包形式，以及标准 UUID@host:port）
//   - 其它协议（vmess/vless/trojan...）只在 v2ray Base64 订阅中使用
//
// client 行为：
//   - v2ray / 其它未知： 通用 Base64 订阅
//   - clash/mihomo/stash/egern/surfboard/loon：只输出 SS 的 Clash YAML
//   - surge：只输出 SS 的 Surge 行
//   - quantumultx：输出 SS + VLESS 的 QX 行（shadowsocks=... / vless=...）
//   - 不对小火箭做适配，小火箭直接用 Base64 订阅

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

  // 2. 解析为节点对象
  const nodes = [];
  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    const lower = line.toLowerCase();

    if (lower.startsWith("ss://")) {
      const n = parseShadowsocksLenient(line);
      nodes.push(n);
    } else if (lower.startsWith("shadowsocks=")) {
      const n = parseShadowsocksQXLenient(line);
      nodes.push(n);
    } else if (lower.startsWith("vless://")) {
      const n = parseVlessLenient(line);
      nodes.push(n);
    } else {
      const scheme = line.split(":", 1)[0].toLowerCase();
      nodes.push({ raw: line, scheme, type: scheme });
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
    outText = buildV2raySubscription(nodes);
  } else if (clashClients.has(client)) {
    outText = buildClashConfig(nodes);
    contentType = "text/yaml; charset=utf-8";
  } else if (client === "surge") {
    outText = buildSurgeConfig(nodes);
  } else if (client === "quantumultx") {
    outText = buildQuantumultXConfig(nodes);
  } else {
    outText = buildV2raySubscription(nodes);
  }

  return new Response(outText, {
    status: 200,
    headers: { "content-type": contentType },
  });
}

/* ========== Base64 & UTF-8 ========== */

function safeBase64Decode(input) {
  try {
    let s = (input || "").trim();
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = (-s.length) % 4;
    if (pad > 0) s += "=".repeat(pad);
    return decodeURIComponent(escape(atob(s)));
  } catch (_e) {
    return "";
  }
}

function utf8ToBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}

/* ========== Shadowsocks 解析：宽松 ss:// URL ========== */

function parseShadowsocksLenient(uri) {
  try {
    let u = uri.replace(/^ss:\/\//i, "");

    // 备注（# 后）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      try {
        name = decodeURIComponent(u.slice(hashIndex + 1));
      } catch (_) {
        name = u.slice(hashIndex + 1);
      }
      u = u.slice(0, hashIndex);
    }

    let userinfoPart = "";
    let serverPart = "";

    const atIndex = u.lastIndexOf("@");
    if (atIndex !== -1) {
      userinfoPart = u.slice(0, atIndex);
      serverPart = u.slice(atIndex + 1);
    } else {
      const decoded = safeBase64Decode(u);
      if (decoded && decoded.includes("@")) {
        const idx = decoded.indexOf("@");
        userinfoPart = decoded.slice(0, idx);
        serverPart = decoded.slice(idx + 1);
      } else {
        serverPart = u;
      }
    }

    // userinfo 可能还是 BASE64(method:pwd)
    let userinfo = userinfoPart;
    if (userinfo && !userinfo.includes(":")) {
      const decodedUser = safeBase64Decode(userinfo);
      if (decodedUser && decodedUser.includes(":")) {
        userinfo = decodedUser;
      }
    }

    let cipher = "aes-128-gcm";
    let password = "";

    if (userinfo && userinfo.includes(":")) {
      const idx = userinfo.indexOf(":");
      cipher = userinfo.slice(0, idx);
      password = userinfo.slice(idx + 1);
    }

    // server:port?query
    let hostPortRaw = serverPart;
    let queryStr = "";
    const qIndex = serverPart.indexOf("?");
    if (qIndex !== -1) {
      hostPortRaw = serverPart.slice(0, qIndex);
      queryStr = serverPart.slice(qIndex + 1);
    }
    hostPortRaw = (hostPortRaw || "").trim();

    let server = hostPortRaw || "0.0.0.0";
    let port = 8388;
    const m = /:(\d+)$/.exec(hostPortRaw);
    if (m) {
      port = parseInt(m[1], 10) || 8388;
      server = hostPortRaw.slice(0, m.index);
    }

    // 解析混淆
    let obfs = "";
    let obfsHost = "";
    let plugin = "";
    let pluginPath = "/";

    if (queryStr) {
      const q = new URLSearchParams(queryStr);
      const pluginParam = q.get("plugin") || "";

      if (pluginParam && pluginParam.includes("obfs-local")) {
        plugin = "obfs";

        obfs = q.get("obfs") || "";
        obfsHost = q.get("obfs-host") ? decodeURIComponent(q.get("obfs-host")) : "";
        pluginPath = q.get("obfs-uri") || pluginPath;

        if (!obfs) {
          const mm = /obfs=([^;]+)/.exec(pluginParam);
          if (mm) obfs = mm[1];
        }
        if (!obfsHost) {
          const mh = /obfs-host=([^;]+)/.exec(pluginParam);
          if (mh) obfsHost = decodeURIComponent(mh[1] || "");
        }
        if (!pluginPath || pluginPath === "/") {
          const mp = /obfs-uri=([^;]+)/.exec(pluginParam);
          if (mp) pluginPath = mp[1] || "/";
        }
      }
    }

    return {
      raw: uri,
      scheme: "ss",
      type: "ss",

      name: name || `${server}:${port}`,
      server,
      port,
      cipher,
      password,

      plugin,
      pluginMode: obfs,
      pluginHost: obfsHost,
      pluginPath,

      obfs,
      obfsHost,
      path: pluginPath || "/",
    };
  } catch (_e) {
    return {
      raw: uri,
      scheme: "ss",
      type: "ss",
      name: uri,
      server: "0.0.0.0",
      port: 8388,
      cipher: "aes-128-gcm",
      password: "password",
      plugin: "",
      pluginMode: "",
      pluginHost: "",
      pluginPath: "/",
      obfs: "",
      obfsHost: "",
      path: "/",
    };
  }
}

/* ========== Shadowsocks 解析：QX 行，宽松 ========== */

function parseShadowsocksQXLenient(line) {
  try {
    const parts = line.split(",");
    if (!parts.length) throw new Error("empty qx line");

    const first = parts[0].trim(); // shadowsocks=server:port
    const mh = /^shadowsocks=(.+?):(\d+)$/.exec(first);
    let server = "0.0.0.0";
    let port = 8388;
    if (mh) {
      server = mh[1];
      port = parseInt(mh[2], 10) || 8388;
    }

    let method = "aes-128-gcm";
    let password = "";
    let obfs = "";
    let obfsHost = "";
    let name = `${server}:${port}`;

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
          obfs = value;
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

      name,
      server,
      port,
      cipher: method,
      password,

      plugin: obfs ? "obfs" : "",
      pluginMode: obfs,
      pluginHost: obfsHost,
      pluginPath: "/",

      obfs,
      obfsHost,
      path: "/",
    };
  } catch (_e) {
    return {
      raw: line,
      scheme: "ss",
      type: "ss",
      name: line,
      server: "0.0.0.0",
      port: 8388,
      cipher: "aes-128-gcm",
      password: "password",
      plugin: "",
      pluginMode: "",
      pluginHost: "",
      pluginPath: "/",
      obfs: "",
      obfsHost: "",
      path: "/",
    };
  }
}

/* ========== VLESS 解析：宽松 vless:// ========== */
/**
 * 支持你这类：
 *   vless://BASE64("auto:UUID@host:port")?remarks=NAME
 * 也尽量兼容标准形式：
 *   vless://UUID@host:port?xxx
 */
function parseVlessLenient(uri) {
  try {
    let u = uri.replace(/^vless:\/\//i, "");

    // 先剥离 query
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    let decoded = safeBase64Decode(main);
    let userinfoHostPort = "";

    if (decoded && decoded.includes("@") && decoded.includes(":")) {
      // 形如 auto:UUID@host:port
      userinfoHostPort = decoded;
    } else {
      // 形如 UUID@host:port
      userinfoHostPort = main;
    }

    // 拆 userinfo 与 host:port
    const atIndex = userinfoHostPort.indexOf("@");
    if (atIndex === -1) {
      throw new Error("invalid vless: missing @");
    }
    const userinfo = userinfoHostPort.slice(0, atIndex);
    const hostPortRaw = userinfoHostPort.slice(atIndex + 1);

    // UUID 在 userinfo 里，通常形如 auto:uuid 或直接 uuid
    const parts = userinfo.split(":");
    const uuid = parts[parts.length - 1] || "";

    // host 与 port
    const hostPort = hostPortRaw.trim();
    let host = hostPort || "0.0.0.0";
    let port = 443;
    const m = /:(\d+)$/.exec(hostPort);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPort.slice(0, m.index);
    }

    // 备注：从 query 中取 remarks / name / tag
    let name = `${host}:${port}`;
    if (queryStr) {
      const q = new URLSearchParams(queryStr);
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

    return {
      raw: uri,
      scheme: "vless",
      type: "vless",

      name,
      server: host,
      port,
      uuid,
      encryption: "none",
    };
  } catch (_e) {
    return {
      raw: uri,
      scheme: "vless",
      type: "vless",
      name: uri,
      server: "0.0.0.0",
      port: 443,
      uuid: "",
      encryption: "none",
    };
  }
}

/* ========== host:port 纠正（给 QX / Clash 用） ========== */

function normalizeHostPort(server, port) {
  let host = (server || "").trim();
  let finalPort = port;

  // 去掉 path / query
  const cut = host.search(/[\/\?]/);
  if (cut !== -1) {
    host = host.slice(0, cut);
  }

  // 如果 host 自己带 :数字，就优先用后面的端口
  const m = /^(.*):(\d+)$/.exec(host);
  if (m) {
    host = m[1];
    finalPort = parseInt(m[2], 10) || finalPort;
  }

  if (!Number.isFinite(finalPort) || finalPort <= 0) {
    finalPort = 443;
  }

  return { host, port: finalPort };
}

/* ========== V2Ray 订阅（Base64） ========== */

function buildV2raySubscription(nodes) {
  const text = nodes
    .map((n) => (n.raw || "").trim())
    .filter((s) => s)
    .join("\n");
  if (!text) return "";
  return utf8ToBase64(text);
}

/* ========== Clash YAML（只输出 SS） ========== */

function buildClashConfig(nodes) {
  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const { host, port } = normalizeHostPort(n.server, n.port);
    const name = n.name || `${host}:${port}`;

    lines.push(`  - name: "${escapeYaml(name)}"`);
    lines.push("    type: ss");
    lines.push(`    server: "${escapeYaml(host)}"`);
    lines.push(`    port: ${port}`);
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

/* ========== Surge（只输出 SS） ========== */

function buildSurgeConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const { host, port } = normalizeHostPort(n.server, n.port);
    const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
    const method = n.cipher;
    const password = n.password;

    let line = `${name}=ss,${host},${port},encrypt-method=${method},password="${password}"`;

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

/* ========== Quantumult X（SS + VLESS） ========== */

function buildQuantumultXConfig(nodes) {
  const lines = [];

  for (const n of nodes) {
    if (n.type === "ss") {
      const { host, port } = normalizeHostPort(n.server, n.port);
      const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
      const method = n.cipher;
      const password = n.password;

      const parts = [];
      parts.push(`shadowsocks=${host}:${port}`);
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
    } else if (n.type === "vless") {
      const { host, port } = normalizeHostPort(n.server, n.port);
      const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
      const uuid = n.uuid || "";

      const parts = [];
      // 🟡 这里就是你要的格式：
      // vless=host:port,method=none,password=UUID,tag=NAME
      parts.push(`vless=${host}:${port}`);
      parts.push("method=none");
      if (uuid) {
        parts.push(`password=${uuid}`);
      }
      parts.push(`tag=${name}`);

      lines.push(parts.join(","));
    }
  }

  if (!lines.length) {
    return "# no shadowsocks/vless nodes\n";
  }
  return lines.join("\n") + "\n";
}