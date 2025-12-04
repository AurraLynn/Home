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
  const rawLines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  // 先展开可能是 Base64 的订阅内容（例如：c3M6Ly9... 这种）
  const lines = expandBase64Lines(rawLines);

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
 * 展开纯 Base64 订阅（例如：c3M6Ly9ZV1Z6... -> 里面其实是 ss://...）
 */
function expandBase64Lines(lines) {
  const result = [];
  for (const l of lines) {
    const s = l.trim();
    if (!isBase64Like(s)) {
      result.push(s);
      continue;
    }

    try {
      const decoded = safeAtob(s);
      // 如果解出来里面含有 "://", 基本可以判断是订阅内容
      if (decoded.includes("://")) {
        decoded
          .replace(/\r\n/g, "\n")
          .split("\n")
          .map((x) => x.trim())
          .filter((x) => x.length > 0)
          .forEach((x) => result.push(x));
        continue;
      } else {
        // 解出来不是节点就按原样保留
        result.push(s);
      }
    } catch (e) {
      // 解码失败，按原样保留
      result.push(s);
    }
  }
  return result;
}

function isBase64Like(str) {
  if (!str || str.length < 8) return false;
  if (/[^A-Za-z0-9+/=_-]/.test(str)) return false;
  // 很短的一串一般不是订阅
  return true;
}

/**
 * 解析单行：识别协议 + 尽量拆字段
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
      // 其他协议先只记录 raw + type，后面有需要再精细解析
    }
  } catch (e) {
    parsed.extra = parsed.extra || {};
    parsed.extra.error = "parse_error: " + String(e);
  }

  if (!parsed.name) {
    parsed.name = guessNameFromRaw(trimmed) || parsed.type.toUpperCase();
  }

  return parsed;
}

/**
 * vmess:// 解析：
 * 支持两种格式：
 * 1) vmess://Base64(JSON)
 * 2) vmess://Base64("auto:uuid@host:port" 或 "uuid@host:port")?path=...&remarks=...&obfsParam=...&obfs=http
 */
function parseVmess(line) {
  const full = line.slice("vmess://".length);
  let main = full; // Base64 部分
  let query = "";  // ? 后面的参数

  const qIndex = full.indexOf("?");
  if (qIndex !== -1) {
    main = full.slice(0, qIndex);
    query = full.slice(qIndex + 1);
  }

  let decoded = "";
  try {
    decoded = safeAtob(main);
  } catch (e) {
    decoded = "";
  }

  const out = {
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
    extra: {},
  };

  // 情况一：老格式 Base64(JSON)
  if (decoded.trim().startsWith("{")) {
    let conf;
    try {
      conf = JSON.parse(decoded);
    } catch (e) {
      conf = null;
    }

    if (conf) {
      const tlsFlag =
        conf.tls === "tls" ||
        conf.tls === "1" ||
        conf.security === "tls" ||
        conf.tls === true;

      out.name = conf.ps || conf.name || null;
      out.server = conf.add || conf.addr || null;
      out.port = conf.port ? Number(conf.port) : null;
      out.uuid = conf.id || conf.uuid || null;
      out.cipher = conf.cipher || "auto";
      out.network = conf.net || "tcp";
      out.tls = tlsFlag;
      out.host =
        conf.host ||
        conf.sni ||
        (conf["ws-opts"] &&
          conf["ws-opts"].headers &&
          conf["ws-opts"].headers.Host) ||
        null;
      out.path =
        conf.path ||
        (conf["ws-opts"] && conf["ws-opts"].path) ||
        null;
      out.extra = conf;
    }
  } else if (decoded) {
    // 情况二：新格式 Base64("auto:uuid@host:port" 或 "uuid@host:port")
    const atIndex = decoded.lastIndexOf("@");
    if (atIndex !== -1) {
      const authPart = decoded.slice(0, atIndex);  // auto:uuid 或 uuid
      const hostPort = decoded.slice(atIndex + 1); // host:port

      const sp = hostPort.split(":");
      out.server = sp[0] || null;
      out.port = sp[1] ? Number(sp[1]) : null;

      const authSegments = authPart.split(":");
      const maybeUuid = authSegments[authSegments.length - 1];
      out.uuid = maybeUuid || null;
      out.cipher = authSegments.length > 1 ? authSegments[0] : "auto";
    }

    out.extra.rawDecoded = decoded;
  }

  // 解析 ? 后面的查询参数：path / remarks / obfsParam / obfs / security / tls / sni
  if (query) {
    const sp = new URLSearchParams(query);
    const q = {};
    sp.forEach((v, k) => {
      q[k] = v;
    });
    out.extra = out.extra || {};
    out.extra.query = q;

    if (!out.path && q.path) out.path = q.path;
    if (!out.host && q.obfsParam) out.host = q.obfsParam;
    if (!out.network && q.obfs) {
      if (q.obfs === "ws") out.network = "ws";
      else if (q.obfs === "http") out.network = "ws";
    }
    if (!out.name && q.remarks) {
      try {
        out.name = decodeURIComponent(q.remarks);
      } catch (e) {
        out.name = q.remarks;
      }
    }
    const sec = q.security || q.tls;
    if (sec === "tls") out.tls = true;
  }

  if (!out.network) {
    if (out.path || out.host) out.network = "ws";
    else out.network = "tcp";
  }

  return out;
}

/**
 * ss:// 解析
 * 形式：
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

  const atIndex = decoded.lastIndexOf("@");
  if (atIndex === -1) {
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
 * vless:// 解析
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
 * trojan:// 解析
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
  const tlsFlag = security === "tls" || true; // trojan 一般默认 TLS

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
 * Base64 解码（兼容 URL 安全 & 补齐 =）
 */
function safeAtob(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad !== 0) s += "===";
  return atob(s);
}

/**
 * 从原始行里猜名字（# 后面的部分）
 */
function guessNameFromRaw(raw) {
  const idx = raw.indexOf("#");
  if (idx !== -1) {
    try {
      return decodeURIComponent(raw.slice(idx + 1));
    } catch (e) {
      return raw.slice(idx + 1);
    }
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
