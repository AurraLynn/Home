// functions/api/node-convert.js
//
// 通用节点转换接口：POST /api/node-convert?client=xxx
// 请求体：原始节点内容（可多行，可为订阅 Base64）
// 返回：指定客户端格式的文本（YAML / JSON / 行文本等）
//
// 支持协议（解析阶段）：
// - ss
// - vmess（JSON base64 + "auto:uuid@host:port" base64 两种）
// - vless（标准 URL + 整块 authority base64 机场写法）
// - trojan
//
// 支持 client：
// - clash
// - surge
// - stash / mihomo
// - egern
// - surfboard
// - loon
// - shadowrocket
// - quantumultx
// - sing-box
// - v2ray（★ 只做“原文 → UTF-8 Base64 / 原样返回 Base64”，不重构 URI）
// 未识别 → 默认 v2ray

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  let client = (url.searchParams.get("client") || "").toLowerCase();

  const bodyText = await request.text();
  const rawBody = bodyText || "";

  if (!rawBody.trim()) {
    return new Response("empty body", { status: 400 });
  }

  if (!client) client = "v2ray";

  // ===== 1. v2ray / 通用订阅：完全不解析 URL，只做 Base64 封装 =====
  if (client === "v2ray") {
    const raw = rawBody.trim();

    if (!raw) {
      return new Response("empty body", { status: 400 });
    }

    // 看起来已经是 Base64 订阅（没有 ://），原样返回
    if (!raw.includes("://") && isLikelyBase64(raw)) {
      return new Response(raw, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // 否则：把原始文本整体 UTF-8 → Base64
    const encoded = encodeBase64Utf8(raw);
    return new Response(encoded, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // ===== 2. 其它客户端：解析成 Node 对象，再做格式转换 =====
  let nodes;
  try {
    nodes = parseNodesFromText(rawBody);
  } catch (e) {
    return new Response("parse error: " + e.message, { status: 400 });
  }

  if (!nodes.length) {
    return new Response("no nodes parsed", { status: 400 });
  }

  let out = "";
  switch (client) {
    case "clash":
      out = toClash(nodes);
      break;
    case "surge":
      out = toSurge(nodes);
      break;
    case "stash":
    case "mihomo":
      out = toStashLike(nodes);
      break;
    case "egern":
      out = toEgern(nodes);
      break;
    case "surfboard":
      out = toSurfboard(nodes);
      break;
    case "loon":
      out = toLoon(nodes);
      break;
    case "shadowrocket":
      out = toShadowrocket(nodes);
      break;
    case "quantumultx":
      out = toQuantumultX(nodes);
      break;
    case "sing-box":
    case "singbox":
      out = toSingBox(nodes);
      break;
    default:
      out = toV2RaySubscription(nodes);
      break;
  }

  const headers = new Headers();
  if (client === "sing-box" || client === "singbox") {
    headers.set("content-type", "application/json; charset=utf-8");
  } else {
    headers.set("content-type", "text/plain; charset=utf-8");
  }

  return new Response(out, {
    status: 200,
    headers,
  });
}

/* -------------------------------------------------------------------------- */
/*  解析：把原始文本（含 Base64 订阅）解析成统一 Node 对象数组                */
/* -------------------------------------------------------------------------- */

/**
 * Node 统一结构：
 * {
 *   type: 'ss' | 'vmess' | 'vless' | 'trojan',
 *   name: '',
 *   server: '',
 *   port: 443,
 *   cipher: '',
 *   password: '',
 *   uuid: '',
 *   network: 'tcp' | 'ws',
 *   path: '',
 *   host: '',
 *   tls: false,
 *   sni: '',
 *   alpn: [],
 *   udp: false,
 *   tfo: false,
 *   plugin: '',
 *   obfs: '',
 *   obfsHost: '',
 *   xtls: '',
 *   pbk: '',
 *   flow: '',
 *   raw: '原始行'
 * }
 */

function parseNodesFromText(text) {
  const nodes = [];
  const raw = text.trim();

  // 整体像 Base64 订阅：没有 "://", 且字符集符合 Base64
  if (!raw.includes("://") && isLikelyBase64(raw)) {
    const decoded = safeBase64Decode(raw);
    if (decoded && decoded.includes("://")) {
      return parseNodesFromText(decoded);
    }
  }

  // 按行处理
  const lines = raw.split(/\r?\n/);
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//")) continue;

    const parts = line.split(/\s+/);
    for (let part of parts) {
      const s = part.trim();
      if (!s) continue;

      if (s.includes("://")) {
        const node = parseSingleUri(s);
        if (node) {
          node.raw = s;
          nodes.push(node);
        }
        continue;
      }

      // 整行没有协议头：尝试 Base64 单个节点
      if (isLikelyBase64(s)) {
        const decoded = safeBase64Decode(s);
        if (decoded && decoded.includes("://")) {
          const subNodes = parseNodesFromText(decoded);
          subNodes.forEach((n) => {
            if (!n.raw) n.raw = decoded;
            nodes.push(n);
          });
          continue;
        }
      }
    }
  }

  return nodes;
}

function isLikelyBase64(str) {
  const s = str.replace(/\s+/g, "");
  if (!s) return false;
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) return false;
  return s.length >= 8;
}

function safeBase64Decode(str) {
  try {
    const s = str.replace(/\s+/g, "");
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    return atob(s + pad);
  } catch (e) {
    return "";
  }
}

function parseSingleUri(uri) {
  try {
    if (uri.startsWith("vmess://")) {
      return parseVmess(uri);
    }
    if (uri.startsWith("vless://")) {
      return parseVlessOrTrojan(uri, "vless");
    }
    if (uri.startsWith("trojan://")) {
      return parseVlessOrTrojan(uri, "trojan");
    }
    if (uri.startsWith("ss://")) {
      return parseShadowsocks(uri);
    }
  } catch (e) {
    return null;
  }
  return null;
}

/* ---------------------- Shadowsocks 解析（含混淆） ---------------------- */


  
    function parseShadowsocks(uri) {
  // 去掉 ss://
  let u = uri.replace(/^ss:\/\//, "");

  // 提取备注（# 后面）
  let name = "";
  const hashIndex = u.indexOf("#");
  if (hashIndex !== -1) {
    name = decodeURIComponent(u.slice(hashIndex + 1));
    u = u.slice(0, hashIndex);
  }

  // 拆 userinfo 和 server 部分：userinfo@server:port?query
  let userinfo = "";
  let serverPart = "";
  const atIndex = u.indexOf("@");
  if (atIndex !== -1) {
    userinfo = u.slice(0, atIndex);
    serverPart = u.slice(atIndex + 1);
  } else {
    // 整体是 base64(userinfo@server:port) 的写法
    const decodedWhole = safeBase64Decode(u);
    if (decodedWhole && decodedWhole.includes("@")) {
      const idx = decodedWhole.indexOf("@");
      userinfo = decodedWhole.slice(0, idx);
      serverPart = decodedWhole.slice(idx + 1);
    } else {
      throw new Error("invalid ss uri");
    }
  }

  // userinfo 可能还是 base64(method:password)
  if (!userinfo.includes(":")) {
    const decodedUser = safeBase64Decode(userinfo);
    if (decodedUser && decodedUser.includes(":")) {
      userinfo = decodedUser;
    }
  }

  // 只在第一个 : 分隔，后面全是密码（密码里可以有冒号）
  const colonIndex = userinfo.indexOf(":");
  if (colonIndex === -1) {
    throw new Error("invalid ss userinfo");
  }
  const method = userinfo.slice(0, colonIndex);          // chacha20-ietf-poly1305
  const password = userinfo.slice(colonIndex + 1);       // t0srmdxrm...

  // server:port?query
  const [hostPort, queryStr = ""] = serverPart.split("?");
  const lastColon = hostPort.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error("invalid ss host/port");
  }
  const server = hostPort.slice(0, lastColon);           // 172.237.6.53
  const port = Number(hostPort.slice(lastColon + 1));    // 2377

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
      if (mMode) pluginMode = mMode[1];                    // tls / http

      const mHost = /obfs-host=([^;]+)/.exec(pluginRaw);
      if (mHost) pluginHost = decodeURIComponent(mHost[1] || "");

      const mPath = /obfs-uri=([^;]+)/.exec(pluginRaw);
      if (mPath) pluginPath = mPath[1] || "/";
    }
  }

  // security=1 可以按需要映射成 udp=true，这里先不乱启：
  const sec = q.get("security");
  const udp = sec === "1" || sec === "true";

  const node = {
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

    // TLS / 混淆（给别的客户端也能用）
    tls: pluginMode === "tls",
    sni: "",
    alpn: [],

    // 兼容字段（之前的代码会用到）
    plugin: plugin,           // "obfs"
    obfs: pluginMode,         // "tls" / "http"
    obfsHost: pluginHost,
    path: pluginPath || "/",
    host: pluginHost,

    // 额外给 Shadowrocket 用的字段
    pluginMode,               // "tls"
    pluginHost,               // "(TG @WangCai2)4b06c71:137573"

    // 其它协议用不到的占位
    xtls: "",
    pbk: "",
    flow: "",
  };

  return node;
}

/* ---------------------------- VMess 解析 ---------------------------- */

function parseVmess(uri) {
  const withoutScheme = uri.replace(/^vmess:\/\//, "");
  const [b64Part, queryStr] = withoutScheme.split("?");
  const q = new URLSearchParams(queryStr || "");

  const decoded = safeBase64Decode(b64Part);
  if (!decoded) {
    throw new Error("invalid vmess base64");
  }

  const tfo = q.get("tfo") === "1" || q.get("tfo") === "true";
  const udp = q.get("udp") === "1" || q.get("udp") === "true";

  // 情况 A：JSON 格式
  if (decoded.trim().startsWith("{")) {
    const cfg = JSON.parse(decoded);

    const node = {
      type: "vmess",
      name:
        (q.get("remarks") && decodeURIComponent(q.get("remarks"))) ||
        cfg.ps ||
        `${cfg.add}:${cfg.port}`,
      server: cfg.add,
      port: Number(cfg.port),
      uuid: cfg.id,
      cipher: cfg.scy || cfg.cipher || "auto",
      network: (cfg.net || "tcp").toLowerCase(),
      udp: udp || !!cfg.udp,
      tfo: tfo || !!cfg.tfo,
      tls: (cfg.tls || "").toLowerCase() === "tls",
      sni: cfg.sni || cfg.host || "",
      alpn: [],
      path: "",
      host: "",
      obfs: "",
      obfsHost: "",
      xtls: "",
      pbk: "",
      flow: "",
    };

    if (node.network === "ws") {
      node.path = cfg.path || "/";
      node.host = cfg.host || node.server;
    }

    return node;
  }

  // 情况 B：auto:uuid@host:port
  if (!decoded.includes("@")) {
    throw new Error("invalid vmess format");
  }

  const [userinfo, addr] = decoded.split("@");
  let cipher = "auto";
  let uuid = userinfo;
  if (userinfo.includes(":")) {
    const idx = userinfo.indexOf(":");
    cipher = userinfo.slice(0, idx) || "auto";
    uuid = userinfo.slice(idx + 1) || "";
  }

  let host = "";
  let port = 443;
  if (addr.includes(":")) {
    const [h, p] = addr.split(":");
    host = h;
    port = Number(p);
  } else {
    host = addr;
  }

  const remarks = q.get("remarks");
  const name =
    (remarks && decodeURIComponent(remarks)) || `${host}:${port}`;

  const tlsParam = (q.get("tls") || "").toLowerCase();
  const tls =
    tlsParam === "1" ||
    tlsParam === "true" ||
    tlsParam === "tls";

  let network = (q.get("net") || q.get("type") || "").toLowerCase();
  const obfs = (q.get("obfs") || "").toLowerCase();
  if (!network && obfs === "websocket") {
    network = "ws";
  }
  if (!network) network = "tcp";

  const sni = q.get("sni") || q.get("peer") || "";
  const path = q.get("path") || "/";
  const hostHeader = q.get("host") || q.get("obfsParam") || "";

  const node = {
    type: "vmess",
    name,
    server: host,
    port,
    uuid,
    cipher,
    network,
    udp,
    tfo,
    tls,
    sni,
    alpn: [],
    path,
    host: hostHeader,
    obfs,
    obfsHost: hostHeader,
    xtls: "",
    pbk: "",
    flow: "",
  };

  return node;
}

/* ------------------- VLESS / TROJAN 解析（含 XTLS） ------------------- */

function parseVlessOrTrojan(uri, type) {
  const url = new URL(uri);
  const q = url.searchParams;

  let userDecoded = "";

  // 情况 1：username 是 Base64（少数机场）
  if (url.username && isLikelyBase64(url.username)) {
    const d = safeBase64Decode(url.username);
    if (d) userDecoded = d;
  }

  let uuid = "";
  let password = "";

  // 先从 userDecoded 里提取 uuid/password
  if (userDecoded) {
    const atIndex = userDecoded.indexOf("@");
    const userPart = atIndex >= 0 ? userDecoded.slice(0, atIndex) : userDecoded;

    const colonIndex = userPart.indexOf(":");
    if (colonIndex >= 0) {
      const right = userPart.slice(colonIndex + 1);
      if (type === "vless") {
        uuid = right || userPart;
      } else {
        password = right || userPart;
      }
    } else {
      if (type === "vless") uuid = userPart;
      else password = userPart;
    }
  }

  // 没拿到的话，fallback 用 URL username
  if (!uuid && type === "vless") {
    uuid = url.username || "";
  }
  if (!password && type === "trojan") {
    password = url.username || "";
  }

  // 先用 URL 的 host / port
  let server = url.hostname;
  let portNum = Number(url.port || 0) || 443;

  // 情况 2：整块 hostname 是 Base64("auto:uuid@host:port" | "none:uuid@host:port")
  if (server && isLikelyBase64(server)) {
    const decoded = safeBase64Decode(server);
    if (decoded && decoded.includes("@")) {
      const [userinfo2, addr2] = decoded.split("@");

      // userinfo2: "auto:uuid" / "none:uuid" / "uuid"
      const colonIdx2 = userinfo2.indexOf(":");
      if (colonIdx2 >= 0) {
        const right2 = userinfo2.slice(colonIdx2 + 1);
        if (type === "vless" && !uuid) uuid = right2 || userinfo2;
        if (type === "trojan" && !password) password = right2 || userinfo2;
      } else {
        if (type === "vless" && !uuid) uuid = userinfo2;
        if (type === "trojan" && !password) password = userinfo2;
      }

      if (addr2) {
        const lastColon = addr2.lastIndexOf(":");
        if (lastColon >= 0) {
          const host = addr2.slice(0, lastColon);
          const portStr = addr2.slice(lastColon + 1);
          if (host) server = host;
          const p = Number(portStr);
          if (p) portNum = p;
        } else {
          if (addr2) server = addr2;
        }
      }
    }
  }

  const remarks = q.get("remarks");
  const hashName = decodeURIComponent(url.hash?.slice(1) || "");
  const name =
    hashName ||
    (remarks ? decodeURIComponent(remarks) : "") ||
    url.username ||
    server;

  const security = (q.get("security") || "").toLowerCase();
  const tlsParam = (q.get("tls") || "").toLowerCase();
  const allowInsecure = q.get("allowInsecure");
  let tls =
    security === "tls" ||
    security === "reality" ||
    tlsParam === "1" ||
    tlsParam === "true";

  if (type === "trojan" && allowInsecure === "1") {
    tls = true;
  }

  const udp = q.get("udp") === "1" || q.get("udp") === "true";
  const tfo = q.get("tfo") === "1" || q.get("tfo") === "true";

  const sni = q.get("sni") || q.get("peer") || "";
  const alpnStr = q.get("alpn");
  const alpn = alpnStr
    ? alpnStr
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  let network = (q.get("type") || "").toLowerCase();
  const obfs = (q.get("obfs") || "").toLowerCase();
  if (!network && obfs === "websocket") {
    network = "ws";
  }
  if (!network) network = "tcp";

  let path = q.get("path") || "";
  let hostHeader = q.get("host") || q.get("obfsParam") || "";

  if (network === "ws" && !path) {
    path = "/";
  }

  const xtls = q.get("xtls") || "";
  const pbk = q.get("pbk") || "";
  let flow = "";
  if (xtls === "2") {
    flow = "xtls-rprx-vision";
  }

  const node = {
    type,
    name,
    server,
    port: portNum,
    uuid: type === "vless" ? uuid : "",
    password: type === "trojan" ? password : "",
    network,
    udp,
    tfo,
    tls,
    sni,
    alpn,
    path,
    host: hostHeader,
    obfs,
    obfsHost: hostHeader,
    xtls,
    pbk,
    flow,
  };

  return node;
}

/* -------------------------------------------------------------------------- */
/*  各客户端格式输出                                                          */
/* -------------------------------------------------------------------------- */

function toClash(nodes) {
  const lines = [];
  lines.push("proxies:");
  for (const n of nodes) {
    const name = safeYamlString(n.name || `${n.server}:${n.port}`);

    if (n.type === "ss") {
      lines.push(`  - name: "${name}"`);
      lines.push(`    type: ss`);
      lines.push(`    server: ${n.server}`);
      lines.push(`    port: ${n.port}`);
      lines.push(`    cipher: ${n.cipher}`);
      lines.push(`    password: "${escapeDoubleQuotes(n.password)}"`);
      if (n.udp) lines.push(`    udp: true`);
      if (n.tfo) lines.push(`    tfo: true`);
      if (n.tls) lines.push(`    tls: true`);

      if (n.obfs) {
        lines.push(`    plugin: obfs`);
        lines.push(`    plugin-opts:`);
        lines.push(`      mode: ${n.obfs}`);
        if (n.obfsHost) lines.push(`      host: ${n.obfsHost}`);
        if (n.path) lines.push(`      path: ${n.path}`);
      }

      continue;
    }

    if (n.type === "vmess") {
      lines.push(`  - name: "${name}"`);
      lines.push(`    type: vmess`);
      lines.push(`    server: ${n.server}`);
      lines.push(`    port: ${n.port}`);
      lines.push(`    uuid: "${n.uuid}"`);
      lines.push(`    alterId: 0`);
      lines.push(`    cipher: ${n.cipher || "auto"}`);
      if (n.udp) lines.push(`    udp: true`);
      if (n.tls) {
        lines.push(`    tls: true`);
        if (n.sni) lines.push(`    sni: ${n.sni}`);
      }
      if (n.network === "ws") {
        lines.push(`    network: ws`);
        lines.push(`    ws-opts:`);
        if (n.path) lines.push(`      path: ${n.path}`);
        if (n.host) {
          lines.push(`      headers:`);
          lines.push(`        Host: ${n.host}`);
        }
      }
      continue;
    }

    if (n.type === "vless" || n.type === "trojan") {
      lines.push(`  - name: "${name}"`);
      lines.push(`    type: ${n.type}`);
      lines.push(`    server: ${n.server}`);
      lines.push(`    port: ${n.port}`);
      if (n.type === "vless") {
        lines.push(`    uuid: "${n.uuid}"`);
        if (n.flow) lines.push(`    flow: ${n.flow}`); // xtls-rprx-vision
      } else {
        lines.push(
          `    password: "${escapeDoubleQuotes(n.password || n.uuid || "")}"`
        );
      }
      if (n.udp) lines.push(`    udp: true`);
      if (n.tls) {
        lines.push(`    tls: true`);
        if (n.sni) lines.push(`    sni: ${n.sni}`);
        if (n.alpn && n.alpn.length) {
          lines.push(`    alpn: [${n.alpn.map((x) => `"${x}"`).join(", ")}]`);
        }
      }
      if (n.network === "ws") {
        lines.push(`    network: ws`);
        lines.push(`    ws-opts:`);
        if (n.path) lines.push(`      path: ${n.path}`);
        if (n.host) {
          lines.push(`      headers:`);
          lines.push(`        Host: ${n.host}`);
        }
      }
      continue;
    }

    if (n.raw) {
      lines.push(`  - name: "${name}"`);
      lines.push(`    type: ss`);
      lines.push(`    server: 127.0.0.1`);
      lines.push(`    port: 0`);
      lines.push(`    cipher: aes-128-gcm`);
      lines.push(`    password: "invalid"`);
    }
  }

  return lines.join("\n");
}

function toSurge(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const parts = [];
      const name = n.name || `${n.server}:${n.port}`;
      parts.push(`${name}=ss`);
      parts.push(n.server);
      parts.push(n.port);
      parts.push(`encrypt-method=${n.cipher}`);
      parts.push(`password="${escapeDoubleQuotes(n.password)}"`);
      if (n.udp) parts.push(`udp-relay=true`);
      if (n.obfs === "tls" || n.obfs === "http") {
        parts.push(`obfs=${n.obfs}`);
        if (n.obfsHost) parts.push(`obfs-host=${n.obfsHost}`);
      }
      lines.push(parts.join(","));
    } else if (n.type === "trojan") {
      const name = n.name || `${n.server}:${n.port}`;
      const parts = [];
      parts.push(`${name}=trojan`);
      parts.push(n.server);
      parts.push(n.port);
      parts.push(`password="${escapeDoubleQuotes(n.password || "")}"`);
      if (n.tls) {
        parts.push("tls=true");
        if (n.sni) parts.push(`sni=${n.sni}`);
      }
      if (n.udp) parts.push(`udp-relay=true`);
      lines.push(parts.join(","));
    }
  }
  return lines.join("\n");
}

function toStashLike(nodes) {
  const arr = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      arr.push({
        type: "ss",
        server: n.server,
        port: n.port,
        cipher: n.cipher,
        password: n.password,
        name: n.name || `${n.server}:${n.port}`,
        udp: n.udp || undefined,
      });
    } else if (n.type === "vmess") {
      arr.push({
        type: "vmess",
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        cipher: n.cipher || "auto",
        tls: n.tls || undefined,
        sni: n.sni || undefined,
        network: n.network || undefined,
        ws_opts:
          n.network === "ws"
            ? {
                path: n.path || "/",
                headers: n.host ? { Host: n.host } : undefined,
              }
            : undefined,
        name: n.name || `${n.server}:${n.port}`,
      });
    }
  }
  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}

function toEgern(nodes) {
  const arr = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      arr.push({
        shadowsocks: {
          name: n.name || `${n.server}:${n.port}`,
          method: n.cipher,
          server: n.server,
          port: n.port,
          password: n.password,
        },
      });
    }
  }
  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}

function toSurfboard(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const name = n.name || `${n.server}:${n.port}`;
      const parts = [];
      parts.push(`${name}=ss`);
      parts.push(n.server);
      parts.push(n.port);
      parts.push(`encrypt-method=${n.cipher}`);
      parts.push(`password=${n.password}`);
      lines.push(parts.join(","));
    }
  }
  return lines.join("\n");
}

function toLoon(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const name = n.name || `${n.server}:${n.port}`;
      lines.push(
        `${name}=shadowsocks,${n.server},${n.port},${n.cipher},"${escapeDoubleQuotes(
          n.password
        )}"`
      );
    }
  }
  return lines.join("\n");
}

function toShadowrocket(nodes) {
  const arr = [];

  for (const n of nodes) {
    // ---------- Shadowsocks ----------
    if (n.type === "ss") {
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

      // simple-obfs：用 plugin + plugin-opts 写法（逻辑上无害）
      if (n.plugin === "obfs" || n.pluginMode || n.pluginHost) {
        obj.plugin = "obfs";
        obj["plugin-opts"] = {
          mode: n.pluginMode || n.obfs || "tls",
        };
        if (n.pluginHost || n.obfsHost) {
          obj["plugin-opts"].host = n.pluginHost || n.obfsHost;
        }
      }

      // ✅ 关键：再额外补一套 obfs / obfs-host / obfs-uri
      // 这个是很多转换器给 Shadowrocket / Surge 用的字段，
      // 小火箭 UI 里的「混淆 / Host」更大概率是认这一套。
      if (n.pluginMode || n.obfs) {
        obj.obfs = n.pluginMode || n.obfs; // "tls" / "http"
      }
      if (n.pluginHost || n.obfsHost) {
        obj["obfs-host"] = n.pluginHost || n.obfsHost;
      }
      if (n.path) {
        obj["obfs-uri"] = n.path;
      }

      arr.push(obj);
      continue;
    }

    // ---------- VMess ----------
    if (n.type === "vmess") {
      const obj = {
        type: "vmess",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        cipher: n.cipher || "auto",
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
        };
        if (n.host) {
          obj["ws-opts"].headers = { Host: n.host };
        }
      }

      if (n.obfs === "http" || n.obfs === "tls") {
        obj.obfs = n.obfs;
        if (n.host) obj["obfs-host"] = n.host;
        if (n.path) obj["obfs-uri"] = n.path;
      }

      arr.push(obj);
      continue;
    }

    // ---------- VLESS ----------
    if (n.type === "vless") {
      const obj = {
        type: "vless",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        "skip-cert-verify": false,
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
        };
        if (n.host) {
          obj["ws-opts"].headers = { Host: n.host };
        }
      }

      arr.push(obj);
      continue;
    }

    // ---------- Trojan ----------
    if (n.type === "trojan") {
      const obj = {
        type: "trojan",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        password: n.password,
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      arr.push(obj);
      continue;
    }
  }

  // 输出为：
  // proxies:
  //   - {...}
  //   - {...}
  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}

    // ---------- VMess ----------
    if (n.type === "vmess") {
      const obj = {
        type: "vmess",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        cipher: n.cipher || "auto",
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
        };
        if (n.host) {
          obj["ws-opts"].headers = { Host: n.host };
        }
      }

      // HTTP/TLS obfs（如 obfs=http，Host 来自 obfsParam）
      if (n.obfs === "http" || n.obfs === "tls") {
        obj.obfs = n.obfs;
        if (n.host) obj["obfs-host"] = n.host;
        if (n.path) obj["obfs-uri"] = n.path;
      }

      arr.push(obj);
      continue;
    }

    // ---------- VLESS ----------
    if (n.type === "vless") {
      const obj = {
        type: "vless",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        "skip-cert-verify": false,
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
        };
        if (n.host) {
          obj["ws-opts"].headers = { Host: n.host };
        }
      }

      // XTLS / PBK：小火箭没有标准字段，只保留在 v2ray 订阅
      // 这里不强行塞，避免客户端报错

      arr.push(obj);
      continue;
    }

    // ---------- Trojan ----------
    if (n.type === "trojan") {
      const obj = {
        type: "trojan",
        name: n.name || `${n.server}:${n.port}`,
        server: n.server,
        port: n.port,
        password: n.password,
      };

      if (n.tls) obj.tls = true;
      if (n.sni) obj.sni = n.sni;
      if (n.udp) obj.udp = true;
      if (n.tfo) obj.tfo = true;

      arr.push(obj);
      continue;
    }
  }

  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}

function toQuantumultX(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const parts = [];
      parts.push(`shadowsocks=${n.server}:${n.port}`);
      parts.push(`method=${n.cipher}`);
      parts.push(`password=${n.password}`);
      if (n.udp) parts.push(`udp-relay=true`);
      if (n.tfo) parts.push(`fast-open=true`);
      if (n.obfs === "tls" || n.obfs === "http") {
        parts.push(`obfs=${n.obfs}`);
        if (n.obfsHost) parts.push(`obfs-host=${n.obfsHost}`);
      }
      parts.push(`tag=${n.name || `${n.server}:${n.port}`}`);
      lines.push(parts.join(","));
    }
  }
  return lines.join("\n");
}

function toSingBox(nodes) {
  const outbounds = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const ob = {
        tag: n.name || `${n.server}:${n.port}`,
        type: "shadowsocks",
        server: n.server,
        server_port: n.port,
        method: n.cipher,
        password: n.password,
      };
      outbounds.push(ob);
    } else if (n.type === "vmess") {
      const ob = {
        tag: n.name || `${n.server}:${n.port}`,
        type: "vmess",
        server: n.server,
        server_port: n.port,
        uuid: n.uuid,
        security: n.cipher || "auto",
      };
      if (n.tls) {
        ob.tls = {
          enabled: true,
          server_name: n.sni || n.host || n.server,
        };
      }
      outbounds.push(ob);
    }
  }
  return JSON.stringify({ outbounds }, null, 2);
}

// 兜底：极端情况用原始 raw 拼个订阅（理论上 v2ray 分支已经直接返回了）
function toV2RaySubscription(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.raw && n.raw.includes("://")) {
      lines.push(n.raw.trim());
      continue;
    }
  }
  const text = lines.join("\n");
  return encodeBase64Utf8(text);
}

/* -------------------------------------------------------------------------- */
/*  小工具函数                                                                */
/* -------------------------------------------------------------------------- */

function safeYamlString(str) {
  if (!str) return "";
  return str.replace(/"/g, '\\"');
}

function escapeDoubleQuotes(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}

// UTF-8 安全版 Base64
function encodeBase64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
