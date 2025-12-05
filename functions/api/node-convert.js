// functions/api/node-convert.js

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

  // 2. 解析节点
  const nodes = [];
  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    const lower = line.toLowerCase();

    if (lower.startsWith("ss://")) {
      // ss URL：绝不抛错，解析失败也返回一个 ss 节点
      const n = parseShadowsocksLenient(line);
      nodes.push(n);
    } else if (lower.startsWith("shadowsocks=")) {
      // QX shadowsocks 行
      const n = parseShadowsocksQXLenient(line);
      nodes.push(n);
    } else {
      // 其它协议：给 V2 订阅用
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
    // 其它一律走 V2 Base64
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

/* ========== Shadowsocks 解析：宽松模式 ========== */
/**
 * 目标：不抛异常，至少保证：
 *   { type: "ss", server, port, cipher, password, name, obfs, obfsHost }
 */
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
      // BASE64(userinfo)@server:port?query  或  userinfo@server:port?query
      userinfoPart = u.slice(0, atIndex);
      serverPart = u.slice(atIndex + 1);
    } else {
      // 可能是 BASE64(method:pwd@server:port?query)
      const decoded = safeBase64Decode(u);
      if (decoded && decoded.includes("@")) {
        const idx = decoded.indexOf("@");
        userinfoPart = decoded.slice(0, idx);
        serverPart = decoded.slice(idx + 1);
      } else {
        // 实在不行就先全给 serverPart，后面再兜底
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

        // 兼容旧写法：都塞在 pluginParam 里
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
    // 极限兜底：至少给出一个 ss 节点，方便你在客户端里看到并手动修改
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

/* ========== Shadowsocks 解析：QX 行，宽松模式 ========== */

function parseShadowsocksQXLenient(line) {
  try {
    const parts = line.split(",");
    if (!parts.length) throw new Error("empty qx line");

    const first = parts[0].trim();
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

/* ========== V2Ray 订阅（Base64） ========== */

function buildV2raySubscription(nodes) {
  const text = nodes
    .map((n) => (n.raw || "").trim())
    .filter((s) => s)
    .join("\n");
  if (!text) return "";
  return utf8ToBase64(text);
}

/* ========== Clash YAML（只输出 SS 节点） ========== */

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

/* ========== Surge（只输出 SS 节点） ========== */

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

/* ========== Quantumult X（只输出 SS 节点） ========== */

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