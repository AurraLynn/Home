// functions/api/node-convert.js
//
// 支持输入：
// -  URL格式
// -  URL/Base64 混合格式
// -  Base64
//
// 支持输出：
// -  Base64
// -  Quantumult X：
//         shadowsocks / UDP
//         shadowsocks / HTTP / UDP
//         VLESS / UDP
//         Trojan / UDP
//         Vmess / UDP
//         Vmess / WEBSOCKET / UDP
//         Vmess / HTTP / UDP
//
// client 行为：
// -  未知UA返回Base64
//
// 已支持的客户端：
// -  Quantumult X
// -  使用Base64订阅的客户端

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const rawText = await request.text();
  const text = rawText || "";

  // 按行拆分，去掉空行与注释
  const linesRaw = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"));

  if (!linesRaw.length) {
    return new Response("", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 仅一行时，尝试整体 Base64 订阅解码
  let lines = linesRaw;
  if (linesRaw.length === 1) {
    const decodedAll = safeBase64Decode(linesRaw[0]);
    if (
      decodedAll &&
      decodedAll !== linesRaw[0] &&
      (decodedAll.includes("://") || decodedAll.includes("\n"))
    ) {
      lines = decodedAll
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("//"));
    }
  }

  // 逐行解析
  const nodes = [];
  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    if (!line) continue;

    const work = line;
    const lower = work.toLowerCase();

    // URL格式：ss://
    if (lower.startsWith("ss://")) {
      nodes.push(parseShadowsocksLenient(work));
      continue;
    }

    // URL格式：vless://
    if (lower.startsWith("vless://")) {
      nodes.push(parseVlessLenient(work));
      continue;
    }

    // URL格式：trojan://
    if (lower.startsWith("trojan://")) {
      nodes.push(parseTrojanLenient(work));
      continue;
    }

    // URL格式：vmess://
    if (lower.startsWith("vmess://")) {
      nodes.push(parseVmessLenient(work));
      continue;
    }

    // 单条Base64：尝试解码成 URL
    const decoded = safeBase64Decode(work);
    if (decoded && decoded !== work) {
      const d = decoded.trim();
      const dl = d.toLowerCase();

      if (dl.startsWith("ss://")) {
        nodes.push(parseShadowsocksLenient(d));
        continue;
      }
      if (dl.startsWith("vless://")) {
        nodes.push(parseVlessLenient(d));
        continue;
      }
      if (dl.startsWith("trojan://")) {
        nodes.push(parseTrojanLenient(d));
        continue;
      }
      if (dl.startsWith("vmess://")) {
        nodes.push(parseVmessLenient(d));
        continue;
      }
      if (dl.startsWith("vmess://")) {
        nodes.push({
          raw: d,
          scheme: "vmess",
          type: "vmess",
        });
        continue;
      }
    }

    // 未知格式：保留原文，用于 Base64 输出
    const scheme = work.split(":", 1)[0].toLowerCase();
    nodes.push({ raw: work, scheme, type: scheme });
  }

  let outText = "";
  let contentType = "text/plain; charset=utf-8";

  // 仅支持：Quantumult X + Base64
  if (client === "quantumultx") {
    outText = buildQuantumultXConfig(nodes);
  } else {
    outText = buildV2raySubscription(nodes);
  }

  return new Response(outText, {
    status: 200,
    headers: { "content-type": contentType },
  });
}

/* ========== Base64 ========== */

function safeBase64Decode(input) {
  try {
    let s = (input || "").trim();
    if (!s) return "";

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

/* ========== Shadowsocks 解析：ss:// ========== */

function parseShadowsocksLenient(uri) {
  try {
    let u = uri.replace(/^ss:\/\//i, "");

    // 备注（#）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.slice(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_) {
        name = remarkPart;
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

    // userinfo 可能是 Base64(method:pwd)
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

    // obfs-local
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
        obfsHost = q.get("obfs-host")
          ? decodeURIComponent(q.get("obfs-host"))
          : "";
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

/* ========== VLESS 解析：vless:// ========== */

function parseVlessLenient(uri) {
  try {
    let u = uri.replace(/^vless:\/\//i, "");

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
      userinfoHostPort = decoded;
    } else {
      userinfoHostPort = main;
    }

    const atIndex = userinfoHostPort.indexOf("@");
    if (atIndex === -1) {
      throw new Error("invalid vless");
    }
    const userinfo = userinfoHostPort.slice(0, atIndex);
    const hostPortRaw = userinfoHostPort.slice(atIndex + 1);

    const parts = userinfo.split(":");
    const uuid = parts[parts.length - 1] || "";

    const hostPort = hostPortRaw.trim();
    let host = hostPort || "0.0.0.0";
    let port = 443;
    const m = /:(\d+)$/.exec(hostPort);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPort.slice(0, m.index);
    }

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

/* ========== Vmess 解析：vmess:// ========== */

function parseVmessLenient(uri) {
  try {
    let u = uri.replace(/^vmess:\/\//i, "");

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

    const atIndex = userinfoHostPort.indexOf("@");
    if (atIndex === -1) {
      throw new Error("invalid vmess");
    }
    const userinfo = userinfoHostPort.slice(0, atIndex);
    const hostPortRaw = userinfoHostPort.slice(atIndex + 1);

    const parts = userinfo.split(":");
    const uuid = parts[parts.length - 1] || "";

    const hostPort = hostPortRaw.trim();
    let host = hostPort || "0.0.0.0";
    let port = 443;
    const m = /:(\d+)$/.exec(hostPort);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPort.slice(0, m.index);
    }

    let name = `${host}:${port}`;
    let obfs = "";
    let obfsHost = "";
    let obfsUri = "";

    if (queryStr) {
      const q = new URLSearchParams(queryStr);

      const r =
        q.get("remarks") ||
        q.get("name") ||
        q.get("tag") ||
        q.get("remark") ||
        q.get("ps");
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }

      const obfsType = (q.get("obfs") || "").toLowerCase();
      const hostFrom = q.get("obfsParam") || q.get("host") || q.get("sni") || "";
      const path = q.get("path") || q.get("obfs-uri") || "/";

      if (obfsType === "websocket" || obfsType === "ws") {
        obfs = "ws";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      } else if (obfsType === "http") {
        obfs = "http";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      }
    }

    return {
      raw: uri,
      scheme: "vmess",
      type: "vmess",

      name,
      server: host,
      port,
      uuid,
      encryption: "auto",

      obfs,
      obfsHost,
      obfsUri,
    };
  } catch (_e) {
    return {
      raw: uri,
      scheme: "vmess",
      type: "vmess",
      name: uri,
      server: "0.0.0.0",
      port: 443,
      uuid: "",
      encryption: "auto",
      obfs: "",
      obfsHost: "",
      obfsUri: "",
    };
  }
}

/* ========== Trojan 解析：trojan:// ========== */

function parseTrojanLenient(uri) {
  try {
    let u = uri.replace(/^trojan:\/\//i, "");

    // 备注（#）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.slice(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_) {
        name = remarkPart;
      }
      u = u.slice(0, hashIndex);
    }

    // 主体 + 参数
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    // password@host:port
    const atIndex = main.lastIndexOf("@");
    let password = "";
    let hostPortRaw = "";
    if (atIndex !== -1) {
      password = main.slice(0, atIndex);
      hostPortRaw = main.slice(atIndex + 1);
    } else {
      hostPortRaw = main;
    }

    try {
      password = decodeURIComponent(password);
    } catch (_e) {}

    hostPortRaw = (hostPortRaw || "").trim();
    let server = hostPortRaw || "0.0.0.0";
    let port = 443;
    const m = /:(\d+)$/.exec(hostPortRaw);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      server = hostPortRaw.slice(0, m.index);
    }

    let allowInsecure = "";
    let peer = "";
    if (queryStr) {
      const q = new URLSearchParams(queryStr);
      allowInsecure =
        q.get("allowInsecure") || q.get("allow_insecure") || "";
      peer = q.get("peer") || q.get("sni") || "";
    }

    const overTls = true;
    const tlsVerification = !(
      allowInsecure === "1" ||
      allowInsecure === "true" ||
      allowInsecure === "yes"
    );
    const tlsHost = peer || server;

    if (!name) {
      name = `${tlsHost}:${port}`;
    }

    return {
      raw: uri,
      scheme: "trojan",
      type: "trojan",

      name,
      server,
      port,
      password,

      overTls,
      tlsVerification,
      tlsHost,
    };
  } catch (_e) {
    return {
      raw: uri,
      scheme: "trojan",
      type: "trojan",
      name: uri,
      server: "0.0.0.0",
      port: 443,
      password: "",
      overTls: true,
      tlsVerification: true,
      tlsHost: "",
    };
  }
}

/* ========== host:port 规范化 ========== */

function normalizeHostPort(server, port) {
  let host = (server || "").trim();
  let finalPort = port;

  const cut = host.search(/[\/\?]/);
  if (cut !== -1) {
    host = host.slice(0, cut);
  }

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

/* ========== 输出：Base64 ========== */

function buildV2raySubscription(nodes) {
  const text = nodes
    .map((n) => (n.raw || "").trim())
    .filter((s) => s)
    .join("\n");
  if (!text) return "";
  return utf8ToBase64(text);
}

/* ========== 输出：Quantumult X ========== */

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
      parts.push(`vless=${host}:${port}`);
      parts.push("method=none");
      if (uuid) {
        parts.push(`password=${uuid}`);
      }
      parts.push(`tag=${name}`);

      lines.push(parts.join(","));
    } else if (n.type === "trojan") {
      const { host, port } = normalizeHostPort(n.server, n.port);
      const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
      const password = n.password || "";
      const overTls = n.overTls ? "true" : "false";
      const tlsVerification = n.tlsVerification ? "true" : "false";
      const tlsHost = n.tlsHost || host;

      const parts = [];
      parts.push(`trojan=${host}:${port}`);
      parts.push(`password=${password}`);
      parts.push(`over-tls=${overTls}`);
      parts.push(`tls-verification=${tlsVerification}`);
      if (tlsHost) {
        parts.push(`tls-host=${tlsHost}`);
      }
      parts.push(`tag=${name}`);

      lines.push(parts.join(","));
    } else if (n.type === "vmess") {
      const { host, port } = normalizeHostPort(n.server, n.port);
      const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
      const uuid = n.uuid || "";
      const method = "chacha20-ietf-poly1305";

      const parts = [];
      parts.push(`vmess=${host}:${port}`);
      parts.push(`method=${method}`);
      if (uuid) {
        parts.push(`password=${uuid}`);
      }

      if (n.obfs === "ws") {
        parts.push("obfs=ws");
        if (n.obfsUri) {
          parts.push(`obfs-uri=${n.obfsUri}`);
        }
        if (n.obfsHost) {
          parts.push(`obfs-host=${n.obfsHost}`);
        }
      } else if (n.obfs === "http") {
        parts.push("obfs=http");
        if (n.obfsUri) {
          parts.push(`obfs-uri=${n.obfsUri}`);
        }
        if (n.obfsHost) {
          parts.push(`obfs-host=${n.obfsHost}`);
        }
      }

      parts.push("aead=true");
      parts.push(`tag=${name}`);

      lines.push(parts.join(","));
    }
  }

  if (!lines.length) {
    return "# no shadowsocks/vless/trojan/vmess nodes\n";
  }
  return lines.join("\n") + "\n";
}