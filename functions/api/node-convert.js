// functions/api/node-convert.js
//
// 通用节点转换接口：POST /api/node-convert?client=xxx
// 请求体：原始节点内容（可多行，可为订阅 Base64）
// 返回：指定客户端格式的文本（YAML / JSON / 行文本等）
//
// 支持协议（解析阶段）：
// - ss
// - vmess（JSON base64 + "auto:uuid@host:port" base64 两种）
// - vless（标准 URL + 全 authority base64 机场骚操作）
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
// - v2ray（★ 现在只做“原文 → UTF-8 Base64”，不再重构 URI）
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

  // ===== 特殊处理：v2ray 订阅，完全不解析节点 =====
  if (client === "v2ray") {
    const raw = rawBody.trim();

    if (!raw) {
      return new Response("empty body", { status: 400 });
    }

    // 如果看起来已经是 Base64 订阅（没有 "://")，就原样返回
    if (!raw.includes("://") && isLikelyBase64(raw)) {
      return new Response(raw, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }

    // 否则：把原始文本整体做 UTF-8 Base64
    const encoded = encodeBase64Utf8(raw);
    return new Response(encoded, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // ===== 其它客户端：解析节点对象，再做转换 =====
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
 *   raw: '原始行（给 v2ray 订阅直接用）'
 * }
 */

function parseNodesFromText(text) {
  const nodes = [];
  const raw = text.trim();

  // 情况 1：整体像 Base64 订阅：没有 "://", 且字符集符合 Base64
  if (!raw.includes("://") && isLikelyBase64(raw)) {
    const decoded = safeBase64Decode(raw);
    if (decoded && decoded.includes("://")) {
      return parseNodesFromText(decoded);
    }
  }

  // 情况 2：按行处理
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
          node.raw = s; // ★ 原始节点串
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
  // 1) ss://base64(method:password)@server:port#name
  // 2) ss://method:password@server:port#name
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
    // 整体是 base64(method:password@server:port)
    const decodedWhole = safeBase64Decode(withoutScheme);
    if (decodedWhole && decodedWhole.includes("@")) {
      [userinfo, serverPart] = decodedWhole.split("@");
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

  // ★ 只在第一个冒号处分割，后面全部是密码（支持密码里再带 ':'）
  const colonIndex = userinfo.indexOf(":");
  if (colonIndex === -1) {
    throw new Error("invalid ss userinfo");
  }
  const method = userinfo.slice(0, colonIndex);
  const passwordRaw = userinfo.slice(colonIndex + 1);
  const password = passwordRaw || "";

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
    alpn: [],
    plugin: "",
    obfs: "",
    obfsHost: "",
    path: "",
    host: "",
  };

  const plugin = q.get("plugin");
  if (plugin) {
    node.plugin = plugin;

    // simple-obfs: obfs-local;obfs=tls;obfs-host=xxx;obfs-uri=/
    if (plugin.includes("obfs-local")) {
      const modeMatch = /obfs=([^;]+)/.exec(plugin);
      if (modeMatch) node.obfs = modeMatch[1]; // http / tls
      const hostMatch = /obfs-host=([^;]+)/.exec(plugin);
      if (hostMatch) node.obfsHost = decodeURIComponent(hostMatch[1]);
      const uriMatch = /obfs-uri=([^;]+)/.exec(plugin);
      if (uriMatch) node.path = uriMatch[1];
      if (node.obfs === "tls") {
        node.tls = true;
      }
    }

    // v2ray-plugin
    if (plugin.includes("v2ray-plugin")) {
      node.network = plugin.includes("websocket") ? "ws" : "tcp";
      if (/tls(;|$)/.test(plugin)) {
        node.tls = true;
      }
      const hostMatch = /host=([^;]+)/.exec(plugin);
      if (hostMatch) node.host = hostMatch[1];
      const pathMatch = /path=([^;]+)/.exec(plugin);
      if (pathMatch) node.path = pathMatch[1];
    }
  }

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
  const path = q.get("path") || "";
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
  };

  return node;
}

/* ------------------- VLESS / TROJAN 解析（URL + Base64） ------------------- */

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
  };

  return node;
}

/* -------------------------------------------------------------------------- */
/*  各客户端格式输出（和之前逻辑一致，这里就不改动思路了）                     */
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

      if (n.plugin && n.plugin.includes("obfs-local") && n.obfs) {
        lines.push(`    plugin: obfs`);
        lines.push(`    plugin-opts:`);
        lines.push(`      mode: ${n.obfs}`);
        if (n.obfsHost) lines.push(`      host: ${n.obfsHost}`);
        if (n.path) lines.push(`      path: ${n.path}`);
      } else if (n.plugin && n.plugin.includes("v2ray-plugin")) {
        lines.push(`    plugin: v2ray-plugin`);
        lines.push(`    plugin-opts:`);
        if (n.network === "ws") lines.push(`      mode: websocket`);
        if (n.tls) lines.push(`      tls: true`);
        if (n.host) lines.push(`      host: ${n.host}`);
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
      continue;
    }

    if (n.type === "vmess") {
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
      continue;
    }

    if (n.type === "vless") {
      arr.push({
        type: "vless",
        server: n.server,
        port: n.port,
        uuid: n.uuid,
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
      continue;
    }

    if (n.type === "trojan") {
      arr.push({
        type: "trojan",
        server: n.server,
        port: n.port,
        password: n.password,
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

/**
 * ★ 兜底：当 switch 落到 default 时调用，但理论上现在 v2ray 已经在 onRequestPost 里短路了。
 * 这里保留只是为了极端 fallback。
 */
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
