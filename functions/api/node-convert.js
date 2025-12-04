// functions/api/node-convert.js
//
// 通用节点转换接口：POST /api/node-convert?client=xxx
// 请求体：原始节点内容（可多行，可为订阅 Base64）
// 返回：指定客户端格式的文本（YAML / JSON / 行文本等）
//
// 支持协议（解析阶段）：
// - ss
// - vmess
// - vless
// - trojan
//
// 支持重点字段：
// - udp / tfo
// - tls / security / sni / alpn
// - network / path / host （ws）
// - ss 混淆：obfs-local / v2ray-plugin
//
// 支持客户端（client 参数）：
// - clash        → proxies: YAML（proxy 列表）
// - surge
// - stash
// - mihomo       → 视作 stash-like（JSON）
// - egern
// - surfboard
// - loon
// - shadowrocket
// - quantumultx
// - sing-box
// - v2ray        → Base64 订阅（多行 URI 再整体 Base64）
// 其它 / 未识别 → 同 v2ray

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
 * Node 统一结构（字段并不都必须有）：
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

  // 情况 1：整体看起来像 Base64 订阅：没有 "://", 且大部分是 Base64 字符
  if (!raw.includes("://") && isLikelyBase64(raw)) {
    const decoded = safeBase64Decode(raw);
    if (decoded && decoded.includes("://")) {
      // 递归再解析一次
      return parseNodesFromText(decoded);
    }
  }

  // 情况 2：按行解析，每行可能是：
  // - 单个 URI
  // - Base64 的 URI
  const lines = raw.split(/\r?\n/);
  for (let line of lines) {
    line = line.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("//")) continue;

    // 行内可能有多个 URI（极少数情况），简单按空格切一下
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

      // 不含 "://": 尝试当作 Base64 的单个 URI
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

      // 其它情况先忽略（脚本 / 普通文本）
    }
  }

  return nodes;
}

function isLikelyBase64(str) {
  const s = str.replace(/\s+/g, "");
  if (!s) return false;
  if (!/^[A-Za-z0-9+/=]+$/.test(s)) return false;
  // 太短的基本不是订阅
  return s.length >= 16;
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
    // 忽略错误行
    return null;
  }
  return null;
}

/* ---------------------- Shadowsocks 解析（含混淆） ---------------------- */

function parseShadowsocks(uri) {
  // 可能是：
  // 1) ss://base64(method:password)@server:port#name
  // 2) ss://method:password@server:port#name
  let withoutScheme = uri.replace(/^ss:\/\//, "");
  let name = "";
  const hashIndex = withoutScheme.indexOf("#");
  if (hashIndex !== -1) {
    name = decodeURIComponent(withoutScheme.slice(hashIndex + 1));
    withoutScheme = withoutScheme.slice(0, hashIndex);
  }

  // 检测是否含有 @
  let userinfo = "";
  let serverPart = "";

  if (withoutScheme.includes("@")) {
    [userinfo, serverPart] = withoutScheme.split("@");
  } else {
    // 整体是 base64(method:password@server:port)
    const decoded = safeBase64Decode(withoutScheme);
    if (decoded && decoded.includes("@")) {
      [userinfo, serverPart] = decoded.split("@");
    } else {
      throw new Error("invalid ss uri");
    }
  }

  // userinfo 可能是 base64(method:password)
  if (!userinfo.includes(":")) {
    const decoded = safeBase64Decode(userinfo);
    if (decoded && decoded.includes(":")) {
      userinfo = decoded;
    }
  }

  const [method, password] = userinfo.split(":");
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
      if (hostMatch) node.obfsHost = hostMatch[1];
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
  const b64 = uri.replace(/^vmess:\/\//, "");
  const jsonStr = safeBase64Decode(b64);
  if (!jsonStr) throw new Error("invalid vmess base64");

  const cfg = JSON.parse(jsonStr);

  const node = {
    type: "vmess",
    name: cfg.ps || `${cfg.add}:${cfg.port}`,
    server: cfg.add,
    port: Number(cfg.port),
    uuid: cfg.id,
    cipher: cfg.scy || cfg.cipher || "auto",
    network: (cfg.net || "tcp").toLowerCase(),
    udp: !!cfg.udp,
    tfo: !!cfg.tfo,
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

/* ------------------- VLESS / TROJAN 解析（URL + Query） ------------------- */

function parseVlessOrTrojan(uri, type) {
  const url = new URL(uri);
  const q = url.searchParams;

  const name =
    decodeURIComponent(url.hash?.slice(1) || "") ||
    url.username ||
    url.hostname;

  const security = (q.get("security") || "").toLowerCase();
  const tls = security === "tls" || security === "reality";

  const node = {
    type,
    name,
    server: url.hostname,
    port: Number(url.port || (tls ? 443 : 80)),
    uuid: type === "vless" ? url.username : "",
    password: type === "trojan" ? url.username : "",
    network: (q.get("type") || "tcp").toLowerCase(),
    udp: q.get("udp") === "1" || q.get("udp") === "true",
    tfo: q.get("tfo") === "1" || q.get("tfo") === "true",
    tls,
    sni: q.get("sni") || q.get("peer") || "",
    alpn: [],
    path: "",
    host: "",
  };

  const alpn = q.get("alpn");
  if (alpn) {
    node.alpn = alpn.split(",").map((s) => s.trim()).filter(Boolean);
  }

  if (node.network === "ws") {
    node.path = q.get("path") || "/";
    node.host = q.get("host") || node.server;
  }

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
        lines.push(`      mode: ${n.obfs}`); // http / tls
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

    // 其它类型先原样保留为一个 "raw" 节点（至少不丢）
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
      // 简单版 trojan
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
      // Surfboard 对 udp 也有支持，这里可以按需再补
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
      });
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
        tls: n.tls
          ? {
              enabled: true,
              server_name: n.sni || n.host || n.server,
            }
          : undefined,
      };
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
      const b64 = btoa(userinfo);
      const name = encodeURIComponent(n.name || `${n.server}:${n.port}`);
      const uri = `ss://${b64}@${n.server}:${n.port}#${name}`;
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
      const b64 = btoa(json);
      lines.push(`vmess://${b64}`);
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
  return btoa(text);
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
