// functions/api/node-convert.js
//
// 通用节点转换接口：POST /api/node-convert?client=xxx
// 请求体：原始节点内容（可多行，可为订阅 Base64）
// 返回：指定客户端格式的文本（YAML / JSON / 行文本等）
//
// 支持协议（解析阶段）：
// - ss
// - vmess（JSON base64 + "auto:uuid@host:port" base64 两种）
// - vless（标准 URL + base64 userinfo + 整个 host 被 base64）
// - trojan
//
// 重点字段：
// - udp / tfo
// - tls / security / tls=1 / allowInsecure=1 / sni(peer) / alpn
// - network / path / host （ws + obfs=websocket）
// - ss 混淆：obfs-local / v2ray-plugin 的 obfs / obfs-host / host / path / tls
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
// - v2ray（多行 URI → 再整体 Base64）
// 未识别 → 默认 v2ray

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const bodyText = await request.text();
  if (!bodyText || !bodyText.trim()) {
    return new Response("empty body", { status: 400 });
  }

  let nodes;
  try {
    nodes = parseNodesFromText(bodyText);
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
    case "v2ray":
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
 *   type: 'ss' | 'vmess' | 'vless' | 'trojan' | 'unknown',
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
 *   raw: '原始行'
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
            if (!n.raw) n.raw = s;
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
    return atob(s);
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

  const [method, passwordRaw] = userinfo.split(":");
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
  };

  const plugin = q.get("plugin");
  if (plugin) {
    node.plugin = plugin;

    // simple-obfs: obfs-local;obfs=tls;obfs-host=xxx
    if (plugin.includes("obfs-local")) {
      const modeMatch = /obfs=([^;]+)/.exec(plugin);
      if (modeMatch) node.obfs = modeMatch[1]; // http / tls
      const hostMatch = /obfs-host=([^;]+)/.exec(plugin);
      if (hostMatch) node.obfsHost = decodeURIComponent(hostMatch[1]);
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
    const parts = userinfo.split(":");
    cipher = parts[0] || "auto";
    uuid = parts[1] || "";
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
  let hostDecoded = "";
  let portDecoded = "";

  // 优先处理 username 里的 base64
  if (url.username && isLikelyBase64(url.username)) {
    const d = safeBase64Decode(url.username);
    if (d) userDecoded = d;
  } else if (!url.username && url.hostname && isLikelyBase64(url.hostname)) {
    const d = safeBase64Decode(url.hostname);
    if (d) {
      userDecoded = d;
    }
  }

  let uuid = "";
  let password = "";
  let server = url.hostname;
  let port = url.port;

  if (userDecoded) {
    if (userDecoded.includes("@")) {
      // none:uuid@host:port
      const [userinfo, addr] = userDecoded.split("@");
      const uparts = userinfo.split(":");
      if (type === "vless") {
        uuid = uparts.length >= 2 ? uparts[1] : uparts[0];
      } else {
        password = uparts.length >= 2 ? uparts[1] : uparts[0];
      }
      if (addr.includes(":")) {
        const [h, p] = addr.split(":");
        hostDecoded = h;
        portDecoded = p;
      } else {
        hostDecoded = addr;
      }
    } else {
      const uparts = userDecoded.split(":");
      if (type === "vless") {
        uuid = uparts.length >= 2 ? uparts[1] : uparts[0];
      } else {
        password = uparts.length >= 2 ? uparts[1] : uparts[0];
      }
    }
  }

  if (!uuid && type === "vless") {
    uuid = url.username || "";
  }
  if (!password && type === "trojan") {
    password = url.username || "";
  }

  if (hostDecoded) {
    server = hostDecoded;
  }
  if (!port && portDecoded) {
    port = portDecoded;
  }
  const portNum = Number(port || 0) || 443;

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
/*  各客户端格式输出                                                          */
/* -------------------------------------------------------------------------- */

/* ------------------------------ Clash / Mihomo ------------------------------ */

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

/* --------------------------------- Surge --------------------------------- */

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

/* -------------------------- Stash / Mihomo JSON -------------------------- */

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

/* --------------------------------- Egern --------------------------------- */

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

/* -------------------------------- Surfboard ------------------------------- */

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

/* ---------------------------------- Loon ---------------------------------- */

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

/* ------------------------------- Shadowrocket ------------------------------ */

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

/* ------------------------------ Quantumult X ------------------------------ */

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

/* -------------------------------- Sing-box -------------------------------- */

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

/* ----------------------------- V2Ray 订阅输出 ----------------------------- */

function toV2RaySubscription(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "ss") {
      // ss://base64(method:password)@server:port#name
      const userinfo = `${n.cipher}:${n.password}`;
      const b64User = encodeBase64Utf8(userinfo);
      const name = encodeURIComponent(n.name || `${n.server}:${n.port}`);
      const uri = `ss://${b64User}@${n.server}:${n.port}#${name}`;
      lines.push(uri);
    } else if (n.type === "vmess") {
      const cfg = {
        v: "2",
        ps: n.name || `${n.server}:${n.port}`,
        add: n.server,
        port: String(n.port),
        id: n.uuid,
        aid: "0",
        scy: n.cipher || "auto",
        net: n.network || "tcp",
        type: "none",
        host: n.host || "",
        path: n.path || "",
        tls: n.tls ? "tls" : "",
        sni: n.sni || "",
      };
      const json = JSON.stringify(cfg);
      const b64Json = encodeBase64Utf8(json);
      lines.push(`vmess://${b64Json}`);
    } else if (n.type === "vless") {
      const params = new URLSearchParams();
      params.set("type", n.network || "tcp");
      if (n.tls) params.set("security", "tls");
      if (n.sni) params.set("sni", n.sni);
      if (n.network === "ws") {
        if (n.path) params.set("path", n.path);
        if (n.host) params.set("host", n.host);
      }
      const name = encodeURIComponent(n.name || `${n.server}:${n.port}`);
      const query = params.toString();
      const uri = `vless://${n.uuid}@${n.server}:${n.port}?${query}#${name}`;
      lines.push(uri);
    } else if (n.type === "trojan") {
      const params = new URLSearchParams();
      if (n.tls) params.set("security", "tls");
      if (n.sni) params.set("sni", n.sni);
      if (n.network === "ws") {
        params.set("type", "ws");
        if (n.path) params.set("path", n.path);
        if (n.host) params.set("host", n.host);
      }
      const name = encodeURIComponent(n.name || `${n.server}:${n.port}`);
      const query = params.toString();
      const uri = `trojan://${n.password}@${n.server}:${n.port}?${query}#${name}`;
      lines.push(uri);
    } else if (n.raw) {
      lines.push(n.raw);
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

// UTF-8 安全版 Base64（修复含中文/emoji 节点导致的 1101）
function encodeBase64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}
