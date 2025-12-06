// functions/api/sub/Surge.js
//
// ✅ 这个文件的作用：
//    - 接收原始订阅内容（可能是 Base64、URL、混合格式）
//    - 解析成「节点对象」
//    - 转换成 Surge / Surfboard 兼容的 [Proxy] 行（不含规则部分）
//
// ✅ 支持输入：
//    - URL 格式
//    - URL / Base64 混合格式
//    - Base64（单条或多条）
//
// ✅ 当前支持协议（Surge / Surfboard）：
//    - Shadowsocks / UDP / HTTP(Simple obfs) / TLS(Simple obfs)
//    - Trojan / UDP
//    - VMess / UDP / (可带 WS/TLS 简单信息)
//    - Hysteria2（hy2）/ UDP（基础字段：server/port/password）
//
// ✅ 已支持客户端：
//    - Surge / Surfboard（通过 [Proxy] 段）
//    - 任意食用 Base64 的客户端（由上层 /index.js 控制）
//
// ⚠️注意：这里仅生成「Proxy 行」，不带 [Proxy] 头，你在本地配置中需要:
//
//    [Proxy]
//    (这里把生成的内容粘进去)
//
// 导出函数：
//    export function buildSurge(rawText)
//
// 用法示例（在 functions/api/sub/index.js 中）：
//    import { buildSurge } from './Surge.js';
//    ...
//    const body = buildSurge(pasteContent);

function safeAtobMaybe(str) {
  if (!str) return null;
  try {
    let s = str.trim();
    // 宽松处理 URL-Safe Base64
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad === 2) s += "==";
    else if (pad === 3) s += "=";
    else if (pad === 1) s = s.slice(0, -1);
    return atob(s);
  } catch (e) {
    return null;
  }
}

function explodeInputToLines(rawText) {
  if (!rawText) return [];
  let s = rawText.replace(/\r/g, "").trim();
  if (!s) return [];

  // 多行：直接按行拆
  if (s.includes("\n")) {
    return s
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l);
  }

  // 单行：如果没有 ://，优先按 Base64 整体解
  if (!s.includes("://")) {
    const decoded = safeAtobMaybe(s);
    if (decoded) {
      return decoded
        .replace(/\r/g, "")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l);
    }
  }

  // 默认当成一条 URL
  return [s];
}

// ============== 通用工具 ==============

function tryDecodeURIComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch (e) {
    return str;
  }
}

function makeNameFromTag(hash, fallbackIndex) {
  if (!hash) return `Node-${fallbackIndex}`;
  const cleaned = hash.replace(/^#/, "");
  const name = tryDecodeURIComponent(cleaned).trim();
  return name || `Node-${fallbackIndex}`;
}

// 简单判断是否是 URL（带协议）
function getScheme(line) {
  const m = line.match(/^([a-z0-9+.-]+):\/\//i);
  return m ? m[1].toLowerCase() : "";
}

// ============== Shadowsocks 解析（ss://）=============
//
// 支持两种：
//   1) ss://BASE64(method:password@host:port)#tag
//   2) ss://BASE64(method:password)@host:port?plugin=...#tag
//
// 返回：节点数组（通常只有 1 个）
//   {
//     type: 'ss',
//     server, port, cipher, password,
//     plugin, pluginMode, pluginHost, pluginPath,
//     name
//   }

function parseShadowsocks(line, index) {
  const result = [];
  let work = line.trim();
  if (!work.startsWith("ss://")) return result;
  work = work.slice(5); // 去掉 ss://

  // 分离 tag
  let tagPart = "";
  const hashPos = work.indexOf("#");
  if (hashPos >= 0) {
    tagPart = work.slice(hashPos + 1);
    work = work.slice(0, hashPos);
  }

  // 先看有没有 @
  const atPos = work.indexOf("@");

  let userPart = "";
  let hostPart = "";
  if (atPos === -1) {
    // 形如 Base64(method:password@host:port)
    const decoded = safeAtobMaybe(work);
    if (!decoded) return result;
    const m = decoded.match(/^(.+?):(.+?)@(.+?):(\d+)$/);
    if (!m) return result;
    const cipher = m[1];
    const password = m[2];
    const server = m[3];
    const port = parseInt(m[4], 10);

    result.push({
      type: "ss",
      server,
      port,
      cipher,
      password,
      name: makeNameFromTag(tagPart, index),
    });
    return result;
  } else {
    // 形如 Base64(method:password)@host:port?plugin=...
    userPart = work.slice(0, atPos);
    hostPart = work.slice(atPos + 1);
  }

  const decodedUser = safeAtobMaybe(userPart);
  if (!decodedUser) return result;

  const userSplit = decodedUser.split(":");
  if (userSplit.length < 2) return result;
  const cipher = userSplit[0];
  const password = userSplit.slice(1).join(":");

  // host:port?plugin=...
  let queryPart = "";
  const qPos = hostPart.indexOf("?");
  if (qPos >= 0) {
    queryPart = hostPart.slice(qPos + 1);
    hostPart = hostPart.slice(0, qPos);
  }

  const hp = hostPart.split(":");
  if (hp.length < 2) return result;
  const server = hp[0];
  const port = parseInt(hp[1], 10);

  let plugin = "";
  let pluginMode = "";
  let pluginHost = "";
  let pluginPath = "";

  if (queryPart) {
    // plugin=obfs-local;obfs=tls;obfs-host=xxx;obfs-uri=/
    // 先拆 plugin= 后面的值
    const qp = queryPart.split("&");
    for (const kv of qp) {
      const [kRaw, vRaw] = kv.split("=");
      const k = (kRaw || "").trim();
      const v = (vRaw || "").trim();
      if (!k) continue;
      if (k === "plugin") {
        const pVal = tryDecodeURIComponent(v);
        const segs = pVal.split(";");
        for (const seg of segs) {
          const [pkRaw, pvRaw] = seg.split("=");
          const pk = (pkRaw || "").trim();
          const pv = (pvRaw || "").trim();
          if (!pk) continue;
          if (pk === "obfs") {
            pluginMode = pv; // http / tls
          } else if (pk === "obfs-host") {
            pluginHost = tryDecodeURIComponent(pv);
          } else if (pk === "obfs-uri") {
            pluginPath = tryDecodeURIComponent(pv || "/");
          }
        }
        // 只要 plugin 存在就认定是 simple-obfs
        plugin = "obfs";
      }
    }
  }

  result.push({
    type: "ss",
    server,
    port: Number.isFinite(port) ? port : 0,
    cipher,
    password,
    plugin,
    pluginMode,
    pluginHost,
    pluginPath,
    name: makeNameFromTag(tagPart, index),
  });

  return result;
}

// ============== Trojan 解析（trojan://）=============
//
// trojan://password@host:port?allowInsecure=1&peer=sni&tfo=1#tag
//
// 返回：
//   { type:'trojan', server, port, password, sni, allowInsecure, udp, name }

function parseTrojan(line, index) {
  const result = [];
  if (!line.toLowerCase().startsWith("trojan://")) return result;

  let urlStr = line.trim();
  // new URL 支持未知协议
  let u;
  try {
    u = new URL(urlStr);
  } catch (e) {
    return result;
  }

  const server = u.hostname;
  const port = parseInt(u.port || "443", 10);
  const password = tryDecodeURIComponent(u.username || "");
  const tag = u.hash ? u.hash.slice(1) : "";
  const sp = u.searchParams;

  const allowInsecure = sp.get("allowInsecure") === "1";
  const tfo = sp.get("tfo") === "1";
  const sni = sp.get("peer") || "";

  result.push({
    type: "trojan",
    server,
    port: Number.isFinite(port) ? port : 443,
    password,
    sni,
    allowInsecure,
    udp: true, // Surge 对 trojan 的 UDP relay 默认支持
    tfo,
    name: makeNameFromTag(tag, index),
  });

  return result;
}

// ============== VMess 解析（vmess://）=============
//
// 支持两种：
//  1) vmess://BASE64(JSON)            // 标准 V2RayN
//  2) vmess://BASE64(auth)@host:port?remarks=...&obfs=websocket&obfsParam=host&path=...
//
// 统一返回：
//   {
//     type:'vmess',
//     server, port, uuid,
//     security, network, wsPath, wsHost,
//     tls, sni, aead,
//     name
//   }

function parseVmess(line, index) {
  const result = [];
  if (!line.toLowerCase().startsWith("vmess://")) return result;

  const body = line.slice(8).trim();

  // 情况 A：标准 vmess JSON，形如 vmess://BASE64({"v":"2","ps":...})
  if (!body.includes("@")) {
    const decoded = safeAtobMaybe(body);
    if (!decoded) return result;
    let obj;
    try {
      obj = JSON.parse(decoded);
    } catch (e) {
      return result;
    }
    const server = obj.add || obj.host || "";
    const port = parseInt(obj.port || "0", 10);
    const uuid = obj.id || "";
    const security = obj.scy || obj.security || "auto";
    const network = obj.net || "tcp";
    const wsPath = obj.path || "/";
    const wsHost = obj.host || "";
    const tls = obj.tls === "tls" || obj.tls === "1";
    const sni = obj.sni || obj.host || "";

    result.push({
      type: "vmess",
      server,
      port: Number.isFinite(port) ? port : 0,
      uuid,
      security,
      network,
      wsPath,
      wsHost,
      tls,
      sni,
      aead: true,
      name: obj.ps || `VMess-${index}`,
    });
    return result;
  }

  // 情况 B：你之前给的 auto URL 形式
  let u;
  try {
    u = new URL(line.trim());
  } catch (e) {
    return result;
  }

  const server = u.hostname;
  const port = parseInt(u.port || "0", 10);
  const usernameEnc = u.username || ""; // 这里一般是 Base64(auth)
  const decodedUser = safeAtobMaybe(usernameEnc) || "";
  // 典型为 auto:UUID 或 chacha20-ietf-poly1305:UUID
  const parts = decodedUser.split(":");
  const security = parts[0] || "chacha20-ietf-poly1305";
  const uuid = parts.slice(1).join(":") || decodedUser || usernameEnc;

  const sp = u.searchParams;
  const tag = sp.get("remarks") || (u.hash ? u.hash.slice(1) : "");
  const obfs = (sp.get("obfs") || "").toLowerCase(); // websocket / http / ...
  const obfsParam = sp.get("obfsParam") || "";
  const path = sp.get("path") || "/";

  let network = "tcp";
  let wsPath = "/";
  let wsHost = "";
  let tls = false;
  let sni = "";

  if (obfs === "websocket") {
    network = "ws";
    wsPath = path || "/";
    wsHost = obfsParam || "";
  } else if (obfs === "http") {
    // Surge 上 HTTP obfs 也只能用 ws + 自定义 header 模拟
    network = "ws";
    wsPath = path || "/";
    wsHost = obfsParam || "";
  }

  // 是否 TLS：部分机场用 tls=1 / host 是 HTTPS 域名
  tls = sp.get("tls") === "1" || false;
  sni = obfsParam || "";

  result.push({
    type: "vmess",
    server,
    port: Number.isFinite(port) ? port : 0,
    uuid,
    security,
    network,
    wsPath,
    wsHost,
    tls,
    sni,
    aead: true,
    name: makeNameFromTag(tag, index),
  });

  return result;
}

// ============== VLESS 解析（vless://）=============
//
// vless://UUID@host:port?...#tag
// vless://BASE64(auth)@host:port?...#tag   （Base64 内部一般是 none:UUID、auto:UUID 等）
//
// ⚠️VLESS 本身不是 Surge 协议，这里只解析，方便 Clash 使用。
// 在 Surge 中我们不会输出 VLESS 行。

function parseVless(line, index) {
  const result = [];
  if (!line.toLowerCase().startsWith("vless://")) return result;

  let u;
  try {
    u = new URL(line.trim());
  } catch (e) {
    return result;
  }

  const server = u.hostname;
  const port = parseInt(u.port || "0", 10);
  let idRaw = u.username || "";
  let uuid = idRaw;

  const decoded = safeAtobMaybe(idRaw);
  if (decoded && decoded.includes(":")) {
    const parts = decoded.split(":");
    uuid = parts[1] || decoded;
  }

  const sp = u.searchParams;
  const tag = sp.get("remarks") || (u.hash ? u.hash.slice(1) : "");
  const network = (sp.get("obfs") || sp.get("type") || "tcp").toLowerCase();
  const path = sp.get("path") || "/";
  const host = sp.get("obfsParam") || sp.get("host") || "";
  const tls = sp.get("tls") === "1" || sp.get("security") === "tls";
  const sni = sp.get("peer") || sp.get("sni") || host;

  result.push({
    type: "vless",
    server,
    port: Number.isFinite(port) ? port : 0,
    uuid,
    network,
    wsPath: path,
    wsHost: host,
    tls,
    sni,
    name: makeNameFromTag(tag, index),
  });

  return result;
}

// ============== Hysteria / Hysteria2 解析 =============
//
// 简单支持 URL 形式：
//   hysteria2://password@host:port?obfs=salamander&obfs-password=xxx#tag
//   hy2://password@host:port?...  （部分机场习惯）
//
// 返回：
//   { type:'hysteria2', server, port, password, obfs, obfsPassword, name }

function parseHysteria(line, index) {
  const low = line.toLowerCase();
  if (!low.startsWith("hysteria2://") && !low.startsWith("hy2://")) return [];

  let u;
  try {
    u = new URL(line.trim());
  } catch (e) {
    return [];
  }

  const server = u.hostname;
  const port = parseInt(u.port || "443", 10);
  const password = tryDecodeURIComponent(u.username || "");
  const sp = u.searchParams;
  const obfs = sp.get("obfs") || "";
  const obfsPassword = sp.get("obfs-password") || sp.get("obfsPassword") || "";
  const tag = u.hash ? u.hash.slice(1) : "";

  return [
    {
      type: "hysteria2",
      server,
      port: Number.isFinite(port) ? port : 443,
      password,
      obfs,
      obfsPassword,
      name: makeNameFromTag(tag, index),
    },
  ];
}

// ============== Surge 行构造 =============
//
// SS 行：
//   NAME = ss, host, port, encrypt-method=..., password=..., udp-relay=true, obfs=http, obfs-host=..., obfs-uri=/
//
// Trojan 行：
//   NAME = trojan, host, port, password=pwd, udp-relay=true, sni=..., skip-cert-verify=true
//
// VMess 行：
//   NAME = vmess, host, port, username=UUID, udp-relay=true, vmess-aead=true, ws=true, ws-path=/, ws-headers=Host:xxx, tls=true, sni=xxx
//
// Hysteria2 行：
//   NAME = hysteria2, host, port, password=pwd, download-bandwidth=100

function buildSurgeLine(node, index) {
  const name = (node && node.name) || `Node-${index}`;

  if (!node || !node.type) return null;

  if (node.type === "ss") {
    const parts = [];
    parts.push(`${name} = ss`);
    parts.push(node.server || "0.0.0.0");
    parts.push(String(node.port || 0));
    parts.push(`encrypt-method=${node.cipher || "chacha20-ietf-poly1305"}`);
    parts.push(`password=${JSON.stringify(node.password || "")}`);

    // 开启 UDP
    parts.push("udp-relay=true");

    // 混淆：simple-obfs http/tls
    if (node.plugin === "obfs" && node.pluginMode) {
      parts.push(`obfs=${node.pluginMode}`);
      if (node.pluginHost) {
        parts.push(`obfs-host=${JSON.stringify(node.pluginHost)}`);
      }
      if (node.pluginPath) {
        parts.push(`obfs-uri=${JSON.stringify(node.pluginPath)}`);
      }
    }

    return parts.join(", ");
  }

  if (node.type === "trojan") {
    const parts = [];
    parts.push(`${name} = trojan`);
    parts.push(node.server || "0.0.0.0");
    parts.push(String(node.port || 443));
    parts.push(`password=${JSON.stringify(node.password || "")}`);
    parts.push("udp-relay=true");
    if (node.sni) {
      parts.push(`sni=${JSON.stringify(node.sni)}`);
    }
    if (node.allowInsecure) {
      parts.push("skip-cert-verify=true");
    }
    return parts.join(", ");
  }

  if (node.type === "vmess") {
    const parts = [];
    parts.push(`${name} = vmess`);
    parts.push(node.server || "0.0.0.0");
    parts.push(String(node.port || 0));
    parts.push(`username=${JSON.stringify(node.uuid || "")}`);
    parts.push("udp-relay=true");
    parts.push("vmess-aead=true");

    if (node.network === "ws") {
      parts.push("ws=true");
      parts.push(`ws-path=${JSON.stringify(node.wsPath || "/")}`);
      if (node.wsHost) {
        // Host 头
        parts.push(`ws-headers=${JSON.stringify("Host:" + node.wsHost)}`);
      }
    }

    if (node.tls || node.sni) {
      parts.push("tls=true");
      if (node.sni) {
        parts.push(`sni=${JSON.stringify(node.sni)}`);
      }
      parts.push("skip-cert-verify=true");
    }

    return parts.join(", ");
  }

  if (node.type === "hysteria2") {
    const parts = [];
    parts.push(`${name} = hysteria2`);
    parts.push(node.server || "0.0.0.0");
    parts.push(String(node.port || 443));
    parts.push(`password=${JSON.stringify(node.password || "")}`);
    // 给个保守的下行带宽，避免完全缺少参数
    parts.push("download-bandwidth=100");
    return parts.join(", ");
  }

  // VLESS 不输出到 Surge（协议不兼容）
  return null;
}

// ============== 主入口：buildSurge =============

export function buildSurge(rawText) {
  const lines = explodeInputToLines(rawText);
  const nodes = [];

  let idx = 1;
  for (const line of lines) {
    if (!line || line.startsWith("#")) continue;
    const scheme = getScheme(line);
    let parsed = [];

    if (scheme === "ss") {
      parsed = parseShadowsocks(line, idx);
    } else if (scheme === "trojan") {
      parsed = parseTrojan(line, idx);
    } else if (scheme === "vmess") {
      parsed = parseVmess(line, idx);
    } else if (scheme === "vless") {
      // 仅解析，当前 Surge 不输出 vless 行
      parsed = parseVless(line, idx);
    } else if (scheme === "hysteria2" || scheme === "hy2" || scheme === "hysteria") {
      parsed = parseHysteria(line, idx);
    } else {
      // 非支持协议，忽略
      parsed = [];
    }

    for (const n of parsed) {
      nodes.push(n);
      idx++;
    }
  }

  if (!nodes.length) {
    return "# no supported nodes";
  }

  const outLines = [];
  nodes.forEach((node, i) => {
    const l = buildSurgeLine(node, i + 1);
    if (l) outLines.push(l);
  });

  if (!outLines.length) {
    return "# no surge-compatible nodes";
  }

  return outLines.join("\n") + "\n";
}

export default { buildSurge };
