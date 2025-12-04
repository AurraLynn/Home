// functions/api/node-convert.js
// 通用节点转换入口：POST /api/node-convert?client=<clientName>
// 当前策略：
//
// 1. 只对 client=shadowrocket 做「ss:// → Shadowrocket proxies:」的格式转换（含 obfs-local 混淆）
// 2. 其它 client 一律原样返回文本（不做转换，保证不破坏节点）
// 3. 解析错误不会抛异常，只跳过那条，避免 1101 Worker 错误

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const rawText = await request.text();
  const text = rawText || "";

  // 按行切分，去掉空行
  const lines = text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("//"));

  // 没内容就原样返回
  if (!lines.length) {
    return new Response(text, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 只处理 Shadowrocket，其他客户端一律原样返回
  if (!client || client === "shadowrocket") {
    const ssNodes = [];

    for (const line of lines) {
      if (!line.toLowerCase().startsWith("ss://")) continue;
      try {
        const node = parseShadowsocks(line);
        ssNodes.push(node);
      } catch (e) {
        // 某条解析失败就跳过，不影响其它
      }
    }

    // 如果一条 ss 都没解析出来，就原样返回，不搞事情
    if (!ssNodes.length) {
      return new Response(text, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    const out = toShadowrocket(ssNodes);
    return new Response(out, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 其它 client：保守起见，直接返回原始内容（以后再慢慢加）
  return new Response(text, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ================= 工具函数 ================= */

// 更安全的 Base64 解码，支持 URL 安全变体
function safeBase64Decode(input) {
  try {
    let s = input.trim();
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad === 2) s += "==";
    else if (pad === 3) s += "=";
    else if (pad === 1) s += "===";
    return decodeURIComponent(escape(atob(s)));
  } catch (e) {
    return "";
  }
}

/* =============== Shadowsocks 解析 =============== */

// 支持两种常见写法：
// 1) ss://BASE64(method:password)@server:port?plugin=...
// 2) ss://BASE64(method:password@server:port?plugin=...)
function parseShadowsocks(uri) {
  let u = uri.replace(/^ss:\/\//i, "");

  // 备注（# 后面的部分）
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
    // 形如 BASE64(method:pwd)@server:port?query
    userinfo = u.slice(0, atIndex);
    serverPart = u.slice(atIndex + 1);
  } else {
    // 形如 BASE64(method:pwd@server:port?query)
    const decoded = safeBase64Decode(u);
    if (!decoded || !decoded.includes("@")) {
      throw new Error("invalid ss uri");
    }
    const idx = decoded.indexOf("@");
    userinfo = decoded.slice(0, idx);
    serverPart = decoded.slice(idx + 1);
  }

  // userinfo 仍然可能是 base64(method:pwd)
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
  const method = userinfo.slice(0, colonIndex);
  const password = userinfo.slice(colonIndex + 1);

  const [hostPort, queryStr = ""] = serverPart.split("?");
  const lastColon = hostPort.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error("invalid ss host/port");
  }
  const server = hostPort.slice(0, lastColon);
  const port = Number(hostPort.slice(lastColon + 1));

  const q = new URLSearchParams(queryStr);

  // 解析 plugin（obfs-local;obfs=tls;obfs-host=...;obfs-uri=/）
  const pluginRaw = q.get("plugin") || "";
  let plugin = "";
  let pluginMode = "";
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

  // 一些机场会塞 security=1 之类，这里可以按需映射成 udp
  const sec = q.get("security");
  const udp = sec === "1" || sec === "true";

  return {
    type: "ss",
    name: name || `${server}:${port}`,
    server,
    port,
    cipher: method,
    password,

    // 网络相关
    network: "tcp",
    udp,
    tfo: false,

    // 混淆相关
    plugin,         // "obfs"
    pluginMode,     // "tls" / "http"
    pluginHost,     // "(TG @WangCai2)4b06c71:137573"
    pluginPath,     // "/"
    obfs: pluginMode,
    obfsHost: pluginHost,
    path: pluginPath || "/",
  };
}

/* =============== 输出为 Shadowrocket =============== */

function toShadowrocket(nodes) {
  const arr = [];

  for (const n of nodes) {
    if (n.type !== "ss") continue;

    const obj = {
      type: "ss",
      server: n.server,
      port: n.port,
      cipher: n.cipher,
      password: n.password,
      name: n.name || `${n.server}:${n.port}`,
    };

    if (n.udp) obj.udp = true;
    if (n.tfo) obj.tfo = true;

    // 写成 plugin + plugin-opts（有些工具会用）
    if (n.plugin === "obfs" || n.pluginMode || n.pluginHost) {
      obj.plugin = "obfs";
      obj["plugin-opts"] = {
        mode: n.pluginMode || n.obfs || "tls",
      };
      if (n.pluginHost || n.obfsHost) {
        obj["plugin-opts"].host = n.pluginHost || n.obfsHost;
      }
    }

    // 再额外补一套 obfs / obfs-host / obfs-uri，方便小火箭 UI 识别
    if (n.pluginMode || n.obfs) {
      obj.obfs = n.pluginMode || n.obfs; // "tls" / "http"
    }
    if (n.pluginHost || n.obfsHost) {
      obj["obfs-host"] = n.pluginHost || n.obfsHost;
    }
    if (n.pluginPath || n.path) {
      obj["obfs-uri"] = n.pluginPath || n.path;
    }

    arr.push(obj);
  }

  // proxies:
  //   - {...}
  //   - {...}
  if (!arr.length) {
    // 万一数组空了，防止返回空 YAML，直接给个空 proxies
    return "proxies: []\n";
  }

  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}