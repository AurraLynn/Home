// functions/api/node-parse.js
// 节点识别 + 解析接口
// POST /api/node-parse
// Body: 纯文本，多行节点 / 文本 / 脚本

export async function onRequestPost(context) {
  const { request } = context;

  let text = "";
  try {
    text = await request.text();
  } catch (e) {
    return jsonResponse({ ok: false, error: "无法读取请求内容" }, 400);
  }

  const raw = (text || "").replace(/\r\n/g, "\n");
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const stats = {
    ss: 0,
    vmess: 0,
    vless: 0,
    trojan: 0,
    hysteria: 0,
    hysteria2: 0,
    tuic: 0,
    snell: 0,
    others: 0,
  };

  const nodes = [];

  for (const line of lines) {
    const parsed = parseSingleLine(line);
    stats[parsed.type] = (stats[parsed.type] || 0) + 1;
    nodes.push(parsed);
  }

  return jsonResponse({
    ok: true,
    totalLines: lines.length,
    detected: stats,
    nodes,
  });
}

/**
 * 解析单行内容：识别协议类型 + 尽量解析出字段
 */
function parseSingleLine(line) {
  const trimmed = line.trim();
  const lower = trimmed.toLowerCase();

  let type = "others";

  if (lower.startsWith("ss://")) {
    type = "ss";
  } else if (lower.startsWith("vmess://")) {
    type = "vmess";
  } else if (lower.startsWith("vless://")) {
    type = "vless";
  } else if (lower.startsWith("trojan://")) {
    type = "trojan";
  } else if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
    type = "hysteria2";
  } else if (lower.startsWith("hysteria://") || lower.startsWith("hy://")) {
    type = "hysteria";
  } else if (lower.startsWith("tuic://")) {
    type = "tuic";
  } else if (lower.startsWith("snell://")) {
    type = "snell";
  }

  // 统一结构
  let parsed = {
    type,
    raw: trimmed,
    name: null,
    server: null,
    port: null,
    uuid: null,
    password: null,
    cipher: null,
    network: null,
    tls: null,
    sni: null,
    host: null,
    path: null,
    // extra 用来存放原始 JSON / 未知参数
    extra: {},
  };

  try {
    if (type === "vmess") {
      parsed = { ...parsed, ...parseVmess(trimmed) };
    } else if (type === "ss") {
      parsed = { ...parsed, ...parseSS(trimmed) };
    } else if (type === "vless") {
      parsed = { ...parsed, ...parseVless(trimmed) };
    } else if (type === "trojan") {
      parsed = { ...parsed, ...parseTrojan(trimmed) };
    } else {
      // 其它协议先不细化，后续再扩展
    }
  } catch (e) {
    // 解析失败就保持基础结构 + raw
    parsed.extra.error = "parse_error: " + String(e);
  }

  // 名称兜底
  if (!parsed.name) {
    parsed.name = guessNameFromRaw(trimmed) || parsed.type.toUpperCase();
  }

  return parsed;
}

/**
 * vmess:// 节点解析：Base64(JSON)
 */
function parseVmess(line) {
  const b64 = line.slice("vmess://".length);
  const jsonStr = safeAtob(b64);
  const conf = JSON.parse(jsonStr);

  const tlsFlag =
    conf.tls === "tls" ||
    conf.tls === "1" ||
    conf.security === "tls" ||
    conf.tls === true;

  return {
    name: conf.ps || conf.name || null,
    server: conf.add || conf.addr || null,
    port: conf.port ? Number(conf.port) : null,
    uuid: conf.id || conf.uuid || null,
    cipher: conf.cipher || "auto",
    network: conf.net || "tcp",
    tls: tlsFlag,
    host: conf.host || conf.sni || (conf["ws-opts"] && conf["ws-opts"].headers && conf["ws-opts"].headers.Host) || null,
    path:
      conf.path ||
      (conf["ws-opts"] && conf["ws-opts"].path) ||
      null,
    extra: conf,
  };
}

/**
 * ss:// 节点解析（尽量兼容常见格式）
 * 常见形式：
 *   ss://Base64(method:password@server:port)#name
 *   ss://method:password@server:port#name
 */
function parseSS(line) {
  let body = line.slice("ss://".length);
  let tag = null;

  const hashIndex = body.indexOf("#");
  if (hashIndex !== -1) {
    tag = decodeURIComponent(body.slice(hashIndex + 1));
    body = body.slice(0, hashIndex);
  }

  let decoded = "";
  // 如果 body 看起来是 Base64（不包含 "." "@" 等），优先按 Base64 解析
  const maybeB64 = /^[A-Za-z0-9+/_=-]+$/.test(body);
  if (maybeB64) {
    try {
      decoded = safeAtob(body);
    } catch (e) {
      decoded = body;
    }
  } else {
    decoded = body;
  }

  // decoded 期待形如 method:password@server:port
  const atIndex = decoded.lastIndexOf("@");
  if (atIndex === -1) {
    // 结构不标准，就当未知
    return {
      name: tag,
      extra: { rawDecoded: decoded },
    };
  }

  const methodPass = decoded.slice(0, atIndex);
  const serverPort = decoded.slice(atIndex + 1);

  const colonIndex = methodPass.indexOf(":");
  const method = colonIndex !== -1 ? methodPass.slice(0, colonIndex) : methodPass;
  const password = colonIndex !== -1 ? methodPass.slice(colonIndex + 1) : "";

  const sp = serverPort.split(":");
  const server = sp[0];
  const port = sp[1] ? Number(sp[1]) : null;

  return {
    name: tag || null,
    server,
    port,
    cipher: method || null,
    password: password || null,
    extra: { rawDecoded: decoded },
  };
}

/**
 * vless://
 * 一般形式：
 *   vless://uuid@server:port?encryption=none&security=tls&host=xxx&path=/xxx#name
 */
function parseVless(line) {
  const url = new URL(line);
  const name =
    (url.hash && decodeURIComponent(url.hash.slice(1))) ||
    url.searchParams.get("remarks") ||
    null;

  const server = url.hostname;
  const port = url.port ? Number(url.port) : 443;
  const uuid = url.username || url.searchParams.get("id") || null;

  const security = url.searchParams.get("security");
  const tlsFlag = security === "tls";

  const network = url.searchParams.get("type") || "tcp";
  const host =
    url.searchParams.get("host") ||
    url.searchParams.get("sni") ||
    null;
  const path = url.searchParams.get("path") || null;

  return {
    name,
    server,
    port,
    uuid,
    tls: tlsFlag,
    network,
    host,
    path,
    extra: { query: Object.fromEntries(url.searchParams.entries()) },
  };
}

/**
 * trojan://
 * 一般形式：
 *   trojan://password@server:port?security=tls&sni=xxx#name
 */
function parseTrojan(line) {
  const url = new URL(line);
  const name =
    (url.hash && decodeURIComponent(url.hash.slice(1))) ||
    url.searchParams.get("remarks") ||
    null;

  const server = url.hostname;
  const port = url.port ? Number(url.port) : 443;
  const password = url.username || url.password || null;

  const security = url.searchParams.get("security");
  const tlsFlag = security === "tls" || true; // trojan 默认走 TLS

  const sni =
    url.searchParams.get("sni") ||
    url.hostname ||
    null;

  return {
    name,
    server,
    port,
    password,
    tls: tlsFlag,
    sni,
    extra: { query: Object.fromEntries(url.searchParams.entries()) },
  };
}

/**
 * Base64 解码（带自动补 pad）
 */
function safeAtob(str) {
  // URL 安全 Base64 替换
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad !== 0) s += "===";
  return atob(s);
}

/**
 * 从原始行里猜名字（#后面的部分）
 */
function guessNameFromRaw(raw) {
  const idx = raw.indexOf("#");
  if (idx !== -1) {
    return decodeURIComponent(raw.slice(idx + 1));
  }
  return null;
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
  });
}