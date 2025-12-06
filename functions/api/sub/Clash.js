// functions/api/sub/Clash.js
//
// 支持输入：
// -  URL 格式
// -  URL / Base64 混合格式
// -  Base64（单条、多条、整条订阅）
//
// 支持输出：
// -  Clash / Mihomo：
//         proxies 段
//         shadowsocks / UDP
//         shadowsocks / HTTP / UDP（带 plugin=obfs, plugin-opts.mode=http / tls）
//
// client 行为：
// -  仅处理 Clash / Mihomo，供 /api/sub/Converter 内部调用
//
// 已支持协议：
// -  Shadowsocks

export async function onRequestPost(context) {
  const { request } = context;
  const rawText = await request.text();
  const text = rawText || "";

  // 按行拆分，去掉空行和注释
  const linesRaw = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"));

  if (!linesRaw.length) {
    return new Response("proxies: []\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 单行时尝试整体 Base64 解码
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

  const nodes = [];

  for (const lineRaw of lines) {
    const line = lineRaw.trim();
    if (!line) continue;

    const lower = line.toLowerCase();

    // 只处理 Shadowsocks
    if (lower.startsWith("ss://")) {
      nodes.push(parseShadowsocksLenient(line));
      continue;
    }

    // 尝试当成 Base64 单条节点解码
    const decoded = safeBase64Decode(line);
    if (decoded && decoded !== line) {
      const d = decoded.trim();
      const dl = d.toLowerCase();
      if (dl.startsWith("ss://")) {
        nodes.push(parseShadowsocksLenient(d));
        continue;
      }
    }

    // 未识别协议：Clash.js 当前忽略
  }

  const outText = buildClashProxies(nodes);

  return new Response(outText, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ========== Base64 工具 ========== */

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

/* ========== Shadowsocks 解析：ss:// ========== */

function parseShadowsocksLenient(uri) {
  try {
    let u = uri.replace(/^ss:\/\//i, "");

    // 备注（节点名）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.slice(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_e) {
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
      // ss://Base64(method:password@host:port)
      const decoded = safeBase64Decode(u);
      if (decoded && decoded.includes("@")) {
        const idx = decoded.indexOf("@");
        userinfoPart = decoded.slice(0, idx);
        serverPart = decoded.slice(idx + 1);
      } else {
        serverPart = u;
      }
    }

    // userinfo 可能是 Base64(method:password)
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

    // serverPart 可能带 query
    let hostPortRaw = serverPart;
    let queryStr = "";
    const qIndex = serverPart.indexOf("?");
    if (qIndex !== -1) {
      hostPortRaw = serverPart.slice(0, qIndex);
      queryStr = serverPart.slice(qIndex + 1);
    }
    hostPortRaw = (hostPortRaw || "").trim();

    // 提取 host + port，避免 "host:port/xxx" 导致 NaN
    let server = hostPortRaw || "0.0.0.0";
    let port = 8388;
    const m = /^(.*):(\d+)$/.exec(hostPortRaw);
    if (m) {
      server = m[1];
      port = parseInt(m[2], 10) || 8388;
    }

    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const q = new URLSearchParams(queryStr);
      const pluginParam = q.get("plugin") || "";

      if (pluginParam && pluginParam.includes("obfs-local")) {
        plugin = "obfs";

        pluginMode = q.get("obfs") || "";
        pluginHost = q.get("obfs-host")
          ? decodeURIComponent(q.get("obfs-host"))
          : "";

        if (!pluginMode) {
          const mm = /obfs=([^;]+)/.exec(pluginParam);
          if (mm) pluginMode = mm[1];
        }
        if (!pluginHost) {
          const mh = /obfs-host=([^;]+)/.exec(pluginParam);
          if (mh) pluginHost = decodeURIComponent(mh[1] || "");
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
      pluginMode,
      pluginHost,
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
      password: "",
      plugin: "",
      pluginMode: "",
      pluginHost: "",
    };
  }
}

/* ========== 输出：Clash / Mihomo proxies 段 ========== */

function buildClashProxies(nodes) {
  const proxies = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const server = (n.server || "").trim() || "0.0.0.0";
    const port = Number.isFinite(n.port) && n.port > 0 ? n.port : 8388;
    const cipher = n.cipher || "aes-128-gcm";
    const password = n.password || "";
    let name = n.name || `${server}:${port}`;

    // 名称里不限制 Emoji / 特殊字符，直接交给 JSON
    const proxy = {
      name,
      type: "ss",
      server,
      port,
      cipher,
      password,
      udp: true,
    };

    // HTTP / TLS 混淆：plugin = obfs
    if (n.plugin === "obfs" && n.pluginMode) {
      proxy.plugin = "obfs";
      proxy["plugin-opts"] = {
        mode: n.pluginMode,
      };
      if (n.pluginHost) {
        proxy["plugin-opts"].host = n.pluginHost;
      }
    }

    proxies.push(proxy);
  }

  if (!proxies.length) {
    return "proxies: []\n";
  }

  // 生成：
  // proxies:
  //   - {"name":"..","type":"ss",...}
  const lines = ["proxies:"];
  for (const p of proxies) {
    lines.push("  - " + JSON.stringify(p));
  }
  return lines.join("\n") + "\n";
}