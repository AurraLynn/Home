// functions/api/sub/Clash.js
//
// ✅ 这个文件的作用：
//    - 接收原始订阅内容（可能是 Base64、URL、混合格式）
//    - 解析成「节点对象」
//    - 转换成 Clash / Clash.Meta / Mihomo 兼容的 YAML 段：
//
//      proxies:
//        - { ... 节点1 ... }
//        - { ... 节点2 ... }
//
// ✅ 支持输入：
//    - URL 格式
//    - URL / Base64 混合格式
//    - Base64（单条或多条）
//
// ✅ 当前支持协议（Clash）：
//    - Shadowsocks / UDP / HTTP(Simple obfs) / TLS(Simple obfs)
//    - Trojan / UDP
//    - VMess / UDP / (可带 WS/TLS 简单信息)
//    - VLESS / UDP / (WS + TLS 简单信息)
//    - Hysteria / Hysteria2 / UDP（基础字段：server/port/password）
//
// ✅ 已支持客户端：
//    - Clash / Clash.Meta / Mihomo
//    - 任意食用 Base64 的客户端（由上层 /index.js 控制）
//
// 导出函数：
//    export function buildClash(rawText)
//
// 用法示例（在 functions/api/sub/index.js 中）：
//    import { buildClash } from './Clash.js';
//    ...
//    const body = buildClash(pasteContent);

function safeAtobMaybe(str) {
  if (!str) return null;
  try {
    let s = str.trim();
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

  if (s.includes("\n")) {
    return s
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l);
  }

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

  return [s];
}

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

function getScheme(line) {
  const m = line.match(/^([a-z0-9+.-]+):\/\//i);
  return m ? m[1].toLowerCase() : "";
}

// ====== Shadowsocks 解析（和 Surge.js 保持一致） ======

function parseShadowsocks(line, index) {
  const result = [];
  let work = line.trim();
  if (!work.startsWith("ss://")) return result;
  work = work.slice(5);

  let tagPart = "";
  const hashPos = work.indexOf("#");
  if (hashPos >= 0) {
    tagPart = work.slice(hashPos + 1);
    work = work.slice(0, hashPos);
  }

  const atPos = work.indexOf("@");
  if (atPos === -1) {
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
  }

  const userPart = work.slice(0, atPos);
  const hostPartRaw = work.slice(atPos + 1);

  const decodedUser = safeAtobMaybe(userPart);
  if (!decodedUser) return result;

  const userSplit = decodedUser.split(":");
  if (userSplit.length < 2) return result;
  const cipher = userSplit[0];
  const password = userSplit.slice(1).join(":");

  let hostPart = hostPartRaw;
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
            pluginMode = pv;
          } else if (pk === "obfs-host") {
            pluginHost = tryDecodeURIComponent(pv);
          } else if (pk === "obfs-uri") {
            pluginPath = tryDecodeURIComponent(pv || "/");
          }
        }
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

// ====== Trojan 解析 ======

function parseTrojan(line, index) {
  const result = [];
  if (!line.toLowerCase().startsWith("trojan://")) return result;
  let u;
  try {
    u = new URL(line.trim());
  } catch (e) {
    return result;
  }

  const server = u.hostname;
  const port = parseInt(u.port || "443", 10);
  const password = tryDecodeURIComponent(u.username || "");
  const sp = u.searchParams;
  const tag = u.hash ? u.hash.slice(1) : "";
  const sni = sp.get("peer") || sp.get("sni") || "";
  const allowInsecure = sp.get("allowInsecure") === "1";
  const tfo = sp.get("tfo") === "1";

  result.push({
    type: "trojan",
    server,
    port: Number.isFinite(port) ? port : 443,
    password,
    sni,
    allowInsecure,
    udp: true,
    tfo,
    name: makeNameFromTag(tag, index),
  });

  return result;
}

// ====== VMess 解析 ======

function parseVmess(line, index) {
  const result = [];
  if (!line.toLowerCase().startsWith("vmess://")) return result;

  const body = line.slice(8).trim();

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

  let u;
  try {
    u = new URL(line.trim());
  } catch (e) {
    return result;
  }

  const server = u.hostname;
  const port = parseInt(u.port || "0", 10);
  const usernameEnc = u.username || "";
  const decodedUser = safeAtobMaybe(usernameEnc) || "";
  const parts = decodedUser.split(":");
  const security = parts[0] || "chacha20-ietf-poly1305";
  const uuid = parts.slice(1).join(":") || decodedUser || usernameEnc;

  const sp = u.searchParams;
  const tag = sp.get("remarks") || (u.hash ? u.hash.slice(1) : "");
  const obfs = (sp.get("obfs") || "").toLowerCase();
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
    network = "ws";
    wsPath = path || "/";
    wsHost = obfsParam || "";
  }

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

// ====== VLESS 解析 ======

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

// ====== Hysteria / Hysteria2 解析 ======

function parseHysteria(line, index) {
  const low = line.toLowerCase();
  if (!low.startsWith("hysteria2://") && !low.startsWith("hy2://") && !low.startsWith("hysteria://")) {
    return [];
  }

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

  const type = low.startsWith("hysteria://") ? "hysteria" : "hysteria2";

  return [
    {
      type,
      server,
      port: Number.isFinite(port) ? port : 443,
      password,
      obfs,
      obfsPassword,
      name: makeNameFromTag(tag, index),
    },
  ];
}

// ====== Clash YAML 构造 ======

function buildClashProxy(node) {
  if (!node || !node.type) return null;

  if (node.type === "ss") {
    const out = {
      name: node.name || "SS",
      type: "ss",
      server: node.server,
      port: node.port,
      cipher: node.cipher || "chacha20-ietf-poly1305",
      password: node.password || "",
      udp: true,
    };

    if (node.plugin === "obfs" && node.pluginMode) {
      out.plugin = "obfs";
      out["plugin-opts"] = {
        mode: node.pluginMode,
      };
      if (node.pluginHost) {
        out["plugin-opts"].host = node.pluginHost;
      }
      if (node.pluginPath) {
        out["plugin-opts"].path = node.pluginPath;
      }
    }

    return out;
  }

  if (node.type === "trojan") {
    const out = {
      name: node.name || "Trojan",
      type: "trojan",
      server: node.server,
      port: node.port,
      password: node.password || "",
      udp: true,
    };
    if (node.sni) out.sni = node.sni;
    if (node.allowInsecure) out["skip-cert-verify"] = true;
    return out;
  }

  if (node.type === "vmess") {
    const out = {
      name: node.name || "VMess",
      type: "vmess",
      server: node.server,
      port: node.port,
      uuid: node.uuid || "",
      cipher: "auto",
      udp: true,
      "alterId": 0,
    };

    if (node.tls || node.sni) {
      out.tls = true;
      if (node.sni) out.sni = node.sni;
    }

    if (node.network === "ws") {
      out.network = "ws";
      out["ws-opts"] = {
        path: node.wsPath || "/",
      };
      if (node.wsHost) {
        out["ws-opts"].headers = { Host: node.wsHost };
      }
    }

    return out;
  }

  if (node.type === "vless") {
    const out = {
      name: node.name || "VLESS",
      type: "vless",
      server: node.server,
      port: node.port,
      uuid: node.uuid || "",
      udp: true,
    };

    if (node.tls || node.sni) {
      out.tls = true;
      if (node.sni) out.servername = node.sni;
      out["skip-cert-verify"] = true;
    }

    if (node.network === "ws") {
      out.network = "ws";
      out["ws-opts"] = {
        path: node.wsPath || "/",
      };
      if (node.wsHost) {
        out["ws-opts"].headers = { Host: node.wsHost };
      }
    }

    return out;
  }

  if (node.type === "hysteria" || node.type === "hysteria2") {
    const out = {
      name: node.name || "HY2",
      type: "hysteria2",
      server: node.server,
      port: node.port,
      password: node.password || "",
      udp: true,
    };
    if (node.obfs) {
      out.obfs = node.obfs;
      if (node.obfsPassword) {
        out["obfs-password"] = node.obfsPassword;
      }
    }
    return out;
  }

  return null;
}

// 简单 YAML 序列化（只针对我们构造的平坦对象即可）
function toYaml(obj, indent) {
  const pad = " ".repeat(indent);
  const lines = [];
  for (const [k, v] of Object.entries(obj)) {
    if (v === undefined) continue;
    if (v === null) continue;
    if (typeof v === "object" && !Array.isArray(v)) {
      lines.push(`${pad}${k}:`);
      lines.push(toYaml(v, indent + 2));
    } else if (Array.isArray(v)) {
      lines.push(`${pad}${k}:`);
      for (const item of v) {
        if (typeof item === "object") {
          lines.push(`${pad}  -`);
          lines.push(toYaml(item, indent + 4));
        } else {
          lines.push(`${pad}  - ${JSON.stringify(item)}`);
        }
      }
    } else if (typeof v === "string") {
      // 统一用 JSON.stringify 保证特殊字符安全（emoji / 中文）
      lines.push(`${pad}${k}: ${JSON.stringify(v)}`);
    } else {
      lines.push(`${pad}${k}: ${String(v)}`);
    }
  }
  return lines.join("\n");
}

// ====== 主入口：buildClash ======

export function buildClash(rawText) {
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
      parsed = parseVless(line, idx);
    } else if (scheme === "hysteria2" || scheme === "hy2" || scheme === "hysteria") {
      parsed = parseHysteria(line, idx);
    } else {
      parsed = [];
    }

    for (const n of parsed) {
      nodes.push(n);
      idx++;
    }
  }

  if (!nodes.length) {
    return "proxies: []\n";
  }

  const proxyObjs = [];
  for (const n of nodes) {
    const p = buildClashProxy(n);
    if (p) proxyObjs.push(p);
  }

  if (!proxyObjs.length) {
    return "proxies: []\n";
  }

  const yamlLines = [];
  yamlLines.push("proxies:");
  for (const p of proxyObjs) {
    yamlLines.push("  -");
    yamlLines.push(toYaml(p, 4));
  }

  yamlLines.push(""); // 末尾空行
  return yamlLines.join("\n");
}

export default { buildClash };
