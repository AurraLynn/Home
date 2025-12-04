// functions/api/node-convert.js
//
// 通用节点转换接口：POST /api/node-convert?client=xxx
// 修复版：增强 Base64 解码兼容性，精准处理 obfsParam/path，生成标准 Shadowrocket URI
//

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
    if (!raw) return new Response("empty body", { status: 400 });

    // 如果看起来已经是 Base64 订阅，原样返回
    if (!raw.includes("://") && isLikelyBase64(raw)) {
      return new Response(raw, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // 否则：UTF-8 → Base64
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

  if (!nodes || !nodes.length) {
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
      // 输出 Shadowrocket 专用的 Base64 订阅格式
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
/*  解析核心：支持标准/非标准 Base64 及各类 URI                                  */
/* -------------------------------------------------------------------------- */

function parseNodesFromText(text) {
  const nodes = [];
  const raw = text.trim();

  // 1. 尝试整体 Base64 解码（处理直接把订阅内容作为 body 传进来的情况）
  if (!raw.includes("://") && isLikelyBase64(raw)) {
    const decoded = safeBase64Decode(raw);
    if (decoded && decoded.includes("://")) {
      return parseNodesFromText(decoded);
    }
  }

  // 2. 按行处理
  const lines = raw.split(/\r?\n/);
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//")) continue;

    // 处理一行内可能有多个节点的情况（虽然少见）
    const parts = line.split(/\s+/);
    for (let part of parts) {
      const s = part.trim();
      if (!s) continue;

      // A. 明文 URI
      if (s.includes("://")) {
        const node = parseSingleUri(s);
        if (node) {
          node.raw = s;
          nodes.push(node);
        }
        continue;
      }

      // B. 单个 Base64 节点（如 vmess://... 或 vless://... 的 base64）
      if (isLikelyBase64(s)) {
        const decoded = safeBase64Decode(s);
        if (decoded && decoded.includes("://")) {
          const subNodes = parseNodesFromText(decoded); // 递归解析解码后的内容
          subNodes.forEach((n) => {
            if (!n.raw) n.raw = decoded;
            nodes.push(n);
          });
        }
      }
    }
  }

  return nodes;
}

/**
 * 增强版 Base64 检测：支持 URL-Safe 字符 (-_)
 */
function isLikelyBase64(str) {
  const s = str.replace(/\s+/g, "");
  if (!s) return false;
  // 允许 A-Z, a-z, 0-9, +, /, =, -, _
  if (!/^[A-Za-z0-9+/=\-_]+$/.test(s)) return false;
  return s.length >= 8;
}

/**
 * 增强版 Base64 解码：自动替换 URL-Safe 字符，处理 Padding
 */
function safeBase64Decode(str) {
  try {
    let s = str.replace(/\s+/g, "");
    // 替换 URL-Safe 字符
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    // 补全 Padding
    const pad = "=".repeat((4 - (s.length % 4)) % 4);
    return atob(s + pad);
  } catch (e) {
    return "";
  }
}

function parseSingleUri(uri) {
  try {
    if (uri.startsWith("vmess://")) return parseVmess(uri);
    if (uri.startsWith("vless://")) return parseVlessOrTrojan(uri, "vless");
    if (uri.startsWith("trojan://")) return parseVlessOrTrojan(uri, "trojan");
    if (uri.startsWith("ss://")) return parseShadowsocks(uri);
  } catch (e) {
    // 忽略解析错误的行
    return null;
  }
  return null;
}

/* ---------------------- 解析逻辑：Shadowsocks ---------------------- */
function parseShadowsocks(uri) {
  let withoutScheme = uri.replace(/^ss:\/\//, "");
  let name = "";
  const hashIndex = withoutScheme.indexOf("#");
  if (hashIndex !== -1) {
    name = decodeURIComponent(withoutScheme.slice(hashIndex + 1));
    withoutScheme = withoutScheme.slice(0, hashIndex);
  }

  let userinfo = "";
  let serverPart = "";

  if (withoutScheme.includes("@")) {
    [userinfo, serverPart] = withoutScheme.split("@");
  } else {
    const decodedWhole = safeBase64Decode(withoutScheme);
    if (decodedWhole && decodedWhole.includes("@")) {
      [userinfo, serverPart] = decodedWhole.split("@");
    } else {
      throw new Error("invalid ss uri");
    }
  }

  if (!userinfo.includes(":")) {
    const decodedUser = safeBase64Decode(userinfo);
    if (decodedUser && decodedUser.includes(":")) {
      userinfo = decodedUser;
    }
  }

  const colonIndex = userinfo.indexOf(":");
  if (colonIndex === -1) throw new Error("invalid ss userinfo");
  
  const method = userinfo.slice(0, colonIndex);
  const password = userinfo.slice(colonIndex + 1) || "";

  const [server, portStrAndQuery] = serverPart.split(":");
  const [portStr, queryStr] = portStrAndQuery.split("?");
  const port = Number(portStr);
  const q = new URLSearchParams(queryStr || "");

  const node = {
    type: "ss",
    name: name || `${server}:${port}`,
    server,
    port,
    cipher: method,
    password,
    network: "tcp",
    udp: q.get("udp") === "1" || q.get("udp") === "true",
    tfo: false,
    tls: false,
    sni: "",
    plugin: "",
    obfs: "",
    obfsHost: "",
    path: "",
    host: "",
  };

  const plugin = q.get("plugin");
  if (plugin) {
    node.plugin = plugin;
    // simple-obfs
    if (plugin.includes("obfs-local")) {
      const modeMatch = /obfs=([^;]+)/.exec(plugin);
      if (modeMatch) node.obfs = modeMatch[1];
      const hostMatch = /obfs-host=([^;]+)/.exec(plugin);
      if (hostMatch) node.obfsHost = decodeURIComponent(hostMatch[1]);
      const uriMatch = /obfs-uri=([^;]+)/.exec(plugin);
      if (uriMatch) node.path = uriMatch[1];
      if (node.obfs === "tls") node.tls = true;
    }
    // v2ray-plugin
    if (plugin.includes("v2ray-plugin")) {
      node.network = plugin.includes("websocket") ? "ws" : "tcp";
      if (/tls(;|$)/.test(plugin)) node.tls = true;
      const hostMatch = /host=([^;]+)/.exec(plugin);
      if (hostMatch) node.host = hostMatch[1];
      const pathMatch = /path=([^;]+)/.exec(plugin);
      if (pathMatch) node.path = pathMatch[1];
    }
  }

  return node;
}

/* ---------------------- 解析逻辑：VMess ---------------------- */
function parseVmess(uri) {
  const withoutScheme = uri.replace(/^vmess:\/\//, "");
  const [b64Part, queryStr] = withoutScheme.split("?");
  const q = new URLSearchParams(queryStr || "");
  const decoded = safeBase64Decode(b64Part);
  if (!decoded) throw new Error("invalid vmess base64");

  const tfo = q.get("tfo") === "1" || q.get("tfo") === "true";
  const udp = q.get("udp") === "1" || q.get("udp") === "true";

  // JSON 格式
  if (decoded.trim().startsWith("{")) {
    const cfg = JSON.parse(decoded);
    const node = {
      type: "vmess",
      name: (q.get("remarks") && decodeURIComponent(q.get("remarks"))) || cfg.ps || `${cfg.add}:${cfg.port}`,
      server: cfg.add,
      port: Number(cfg.port),
      uuid: cfg.id,
      cipher: cfg.scy || cfg.cipher || "auto",
      network: (cfg.net || "tcp").toLowerCase(),
      udp: udp || !!cfg.udp,
      tfo: tfo || !!cfg.tfo,
      tls: (cfg.tls || "").toLowerCase() === "tls",
      sni: cfg.sni || cfg.host || "",
      path: "",
      host: "",
    };
    if (node.network === "ws") {
      node.path = cfg.path || "/";
      node.host = cfg.host || node.server;
    }
    return node;
  }

  // 标准格式 auto:uuid@host:port
  if (!decoded.includes("@")) throw new Error("invalid vmess format");
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
  const name = (remarks && decodeURIComponent(remarks)) || `${host}:${port}`;
  const tlsParam = (q.get("tls") || "").toLowerCase();
  const tls = tlsParam === "1" || tlsParam === "true" || tlsParam === "tls";
  
  let network = (q.get("net") || q.get("type") || "").toLowerCase();
  const obfs = (q.get("obfs") || "").toLowerCase();
  if (!network && obfs === "websocket") network = "ws";
  if (!network) network = "tcp";

  const sni = q.get("sni") || q.get("peer") || "";
  const path = q.get("path") || "";
  const hostHeader = q.get("host") || q.get("obfsParam") || "";

  return {
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
  };
}

/* ---------------------- 解析逻辑：VLESS / Trojan ---------------------- */
function parseVlessOrTrojan(uri, type) {
  const url = new URL(uri);
  const q = url.searchParams;

  // 处理 User 部分 Base64
  let userDecoded = "";
  if (url.username && isLikelyBase64(url.username)) {
    const d = safeBase64Decode(url.username);
    if (d) userDecoded = d;
  }

  let uuid = "";
  let password = "";

  if (userDecoded) {
    const atIndex = userDecoded.indexOf("@");
    const userPart = atIndex >= 0 ? userDecoded.slice(0, atIndex) : userDecoded;
    if (type === "vless") uuid = userPart;
    else password = userPart;
  }

  if (!uuid && type === "vless") uuid = url.username || "";
  if (!password && type === "trojan") password = url.username || "";

  let server = url.hostname;
  let portNum = Number(url.port || 0) || 443;

  // 处理 Host 部分 Base64（某些机场写法）
  if (server && isLikelyBase64(server)) {
    const decoded = safeBase64Decode(server);
    if (decoded && decoded.includes("@")) {
      const [userinfo2, addr2] = decoded.split("@");
      const right2 = userinfo2.split(":")[1] || userinfo2;
      if (type === "vless" && !uuid) uuid = right2;
      if (type === "trojan" && !password) password = right2;
      
      if (addr2) {
        const lastColon = addr2.lastIndexOf(":");
        if (lastColon >= 0) {
          server = addr2.slice(0, lastColon);
          portNum = Number(addr2.slice(lastColon + 1)) || portNum;
        } else {
          server = addr2;
        }
      }
    }
  }

  const remarks = q.get("remarks");
  const hashName = decodeURIComponent(url.hash?.slice(1) || "");
  const name = hashName || (remarks ? decodeURIComponent(remarks) : "") || url.username || server;

  const security = (q.get("security") || "").toLowerCase();
  const tlsParam = (q.get("tls") || "").toLowerCase();
  let tls = security === "tls" || security === "reality" || tlsParam === "1" || tlsParam === "true";
  if (type === "trojan" && q.get("allowInsecure") === "1") tls = true;

  const udp = q.get("udp") === "1" || q.get("udp") === "true";
  const tfo = q.get("tfo") === "1" || q.get("tfo") === "true";
  const sni = q.get("sni") || q.get("peer") || "";
  const alpnStr = q.get("alpn");
  const alpn = alpnStr ? alpnStr.split(",").map((s) => s.trim()).filter(Boolean) : [];

  let network = (q.get("type") || "").toLowerCase();
  const obfs = (q.get("obfs") || "").toLowerCase();
  
  // ★ 核心修复：兼容旧格式 obfs=websocket -> network=ws
  if (!network && obfs === "websocket") {
    network = "ws";
  }
  if (!network) network = "tcp";

  let path = q.get("path") || "";
  // ★ 核心修复：兼容旧格式 obfsParam -> host
  let hostHeader = q.get("host") || q.get("obfsParam") || "";

  if (network === "ws" && !path) {
    path = "/";
  }

  return {
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
  };
}

/* -------------------------------------------------------------------------- */
/*  输出格式：Clash                                                           */
/* -------------------------------------------------------------------------- */

function toClash(nodes) {
  const lines = [];
  lines.push("proxies:");
  for (const n of nodes) {
    const name = safeYamlString(n.name || `${n.server}:${n.port}`);
    if (n.type === "ss") {
      lines.push(`  - name: "${name}"\n    type: ss\n    server: ${n.server}\n    port: ${n.port}\n    cipher: ${n.cipher}\n    password: "${escapeDoubleQuotes(n.password)}"`);
      if (n.udp) lines.push(`    udp: true`);
      if (n.tfo) lines.push(`    tfo: true`);
      if (n.plugin && n.plugin.includes("obfs-local") && n.obfs) {
        lines.push(`    plugin: obfs\n    plugin-opts:\n      mode: ${n.obfs}`);
        if (n.obfsHost) lines.push(`      host: ${n.obfsHost}`);
        if (n.path) lines.push(`      path: ${n.path}`);
      }
      continue;
    }
    if (n.type === "vmess") {
      lines.push(`  - name: "${name}"\n    type: vmess\n    server: ${n.server}\n    port: ${n.port}\n    uuid: "${n.uuid}"\n    alterId: 0\n    cipher: ${n.cipher || "auto"}`);
      if (n.udp) lines.push(`    udp: true`);
      if (n.tls) {
        lines.push(`    tls: true`);
        if (n.sni) lines.push(`    sni: ${n.sni}`);
      }
      if (n.network === "ws") {
        lines.push(`    network: ws\n    ws-opts:`);
        if (n.path) lines.push(`      path: ${n.path}`);
        if (n.host) lines.push(`      headers:\n        Host: ${n.host}`);
      }
      continue;
    }
    if (n.type === "vless" || n.type === "trojan") {
      lines.push(`  - name: "${name}"\n    type: ${n.type}\n    server: ${n.server}\n    port: ${n.port}`);
      if (n.type === "vless") lines.push(`    uuid: "${n.uuid}"`);
      else lines.push(`    password: "${escapeDoubleQuotes(n.password || "")}"`);
      if (n.udp) lines.push(`    udp: true`);
      if (n.tls) {
        lines.push(`    tls: true`);
        if (n.sni) lines.push(`    sni: ${n.sni}`);
        if (n.alpn && n.alpn.length) lines.push(`    alpn: [${n.alpn.map((x) => `"${x}"`).join(", ")}]`);
      }
      if (n.network === "ws") {
        lines.push(`    network: ws\n    ws-opts:`);
        if (n.path) lines.push(`      path: ${n.path}`);
        if (n.host) lines.push(`      headers:\n        Host: ${n.host}`);
      }
    }
  }
  return lines.join("\n");
}

/* -------------------------------------------------------------------------- */
/*  输出格式：Shadowrocket (Standard Base64 Subscription)                     */
/* -------------------------------------------------------------------------- */

function toShadowrocket(nodes) {
  const lines = [];
  for (const n of nodes) {
    // VLESS
    if (n.type === "vless") {
      const u = new URL(`vless://${n.uuid}@${n.server}:${n.port}`);
      u.searchParams.set("encryption", "none");
      u.searchParams.set("security", n.tls ? "tls" : "none");
      u.searchParams.set("type", n.network || "tcp");
      
      if (n.host) u.searchParams.set("host", n.host);
      if (n.path) u.searchParams.set("path", n.path);
      if (n.sni) u.searchParams.set("sni", n.sni);
      if (n.tfo) u.searchParams.set("tfo", "1");
      if (n.udp) u.searchParams.set("udp", "1");
      if (n.alpn && n.alpn.length) u.searchParams.set("alpn", n.alpn.join(","));
      
      u.hash = encodeURIComponent(n.name || "");
      lines.push(u.toString());
      continue;
    }

    // VMess
    if (n.type === "vmess") {
      const vmessBody = {
        v: "2",
        ps: n.name || "",
        add: n.server,
        port: n.port,
        id: n.uuid,
        aid: 0,
        scy: n.cipher || "auto",
        net: n.network || "tcp",
        type: "none",
        host: n.host || "",
        path: n.path || "",
        tls: n.tls ? "tls" : "",
        sni: n.sni || ""
      };
      const b64 = encodeBase64Utf8(JSON.stringify(vmessBody));
      lines.push("vmess://" + b64);
      continue;
    }

    // Shadowsocks
    if (n.type === "ss") {
      const userInfo = encodeBase64Utf8(`${n.cipher}:${n.password}`);
      const u = new URL(`ss://${userInfo}@${n.server}:${n.port}`);
      if (n.plugin) u.searchParams.set("plugin", n.plugin);
      u.hash = encodeURIComponent(n.name || "");
      lines.push(u.toString());
      continue;
    }

    // Trojan
    if (n.type === "trojan") {
      const u = new URL(`trojan://${n.password}@${n.server}:${n.port}`);
      u.searchParams.set("security", n.tls ? "tls" : "none");
      if (n.sni) u.searchParams.set("sni", n.sni);
      if (n.host) u.searchParams.set("host", n.host);
      if (n.path) u.searchParams.set("path", n.path);
      if (n.network === "ws") u.searchParams.set("type", "ws");
      u.hash = encodeURIComponent(n.name || "");
      lines.push(u.toString());
      continue;
    }
  }

  // 返回 Base64 编码的 URI 列表（小火箭标准订阅格式）
  return encodeBase64Utf8(lines.join("\n"));
}

/* -------------------------------------------------------------------------- */
/*  其他客户端输出格式                                                        */
/* -------------------------------------------------------------------------- */

function toSurge(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const name = n.name || `${n.server}:${n.port}`;
      const parts = [`${name}=ss`, n.server, n.port, `encrypt-method=${n.cipher}`, `password="${escapeDoubleQuotes(n.password)}"`];
      if (n.udp) parts.push(`udp-relay=true`);
      if (n.obfs === "tls" || n.obfs === "http") {
        parts.push(`obfs=${n.obfs}`);
        if (n.obfsHost) parts.push(`obfs-host=${n.obfsHost}`);
      }
      lines.push(parts.join(","));
    } else if (n.type === "trojan") {
      const name = n.name || `${n.server}:${n.port}`;
      const parts = [`${name}=trojan`, n.server, n.port, `password="${escapeDoubleQuotes(n.password || "")}"`];
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

function toStashLike(nodes) { return toClash(nodes); }

function toEgern(nodes) {
  const arr = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      arr.push({ shadowsocks: { name: n.name || `${n.server}:${n.port}`, method: n.cipher, server: n.server, port: n.port, password: n.password }});
    }
  }
  return "proxies:\n  - " + arr.map((x) => JSON.stringify(x)).join("\n  - ");
}

function toSurfboard(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const name = n.name || `${n.server}:${n.port}`;
      lines.push([`${name}=ss`, n.server, n.port, `encrypt-method=${n.cipher}`, `password=${n.password}`].join(","));
    }
  }
  return lines.join("\n");
}

function toLoon(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const name = n.name || `${n.server}:${n.port}`;
      lines.push(`${name}=shadowsocks,${n.server},${n.port},${n.cipher},"${escapeDoubleQuotes(n.password)}"`);
    }
  }
  return lines.join("\n");
}

function toQuantumultX(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      const parts = [`shadowsocks=${n.server}:${n.port}`, `method=${n.cipher}`, `password=${n.password}`, `tag=${n.name || `${n.server}:${n.port}`}`];
      if (n.udp) parts.push(`udp-relay=true`);
      if (n.tfo) parts.push(`fast-open=true`);
      if (n.obfs === "tls" || n.obfs === "http") {
        parts.push(`obfs=${n.obfs}`);
        if (n.obfsHost) parts.push(`obfs-host=${n.obfsHost}`);
      }
      lines.push(parts.join(","));
    }
  }
  return lines.join("\n");
}

function toSingBox(nodes) {
  const outbounds = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      outbounds.push({ tag: n.name || `${n.server}:${n.port}`, type: "shadowsocks", server: n.server, server_port: n.port, method: n.cipher, password: n.password });
    } else if (n.type === "vmess") {
      const ob = { tag: n.name || `${n.server}:${n.port}`, type: "vmess", server: n.server, server_port: n.port, uuid: n.uuid, security: n.cipher || "auto" };
      if (n.tls) ob.tls = { enabled: true, server_name: n.sni || n.host || n.server };
      outbounds.push(ob);
    }
  }
  return JSON.stringify({ outbounds }, null, 2);
}

function toV2RaySubscription(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.raw && n.raw.includes("://")) {
      lines.push(n.raw.trim());
    }
  }
  return encodeBase64Utf8(lines.join("\n"));
}

/* -------------------------------------------------------------------------- */
/*  辅助函数                                                                  */
/* -------------------------------------------------------------------------- */

function safeYamlString(str) {
  if (!str) return "";
  return str.replace(/"/g, '\\"');
}

function escapeDoubleQuotes(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}

// UTF-8 安全版 Base64 编码
function encodeBase64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
