// functions/api/node-convert.js
// 节点识别 + 转换接口
// POST /api/node-convert?client=xxx
// Body: 纯文本，多行节点 / 订阅内容

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "clash").toLowerCase();

  let text = "";
  try {
    text = await request.text();
  } catch (e) {
    return new Response("无法读取请求内容", { status: 400 });
  }

  const raw = (text || "").replace(/\r\n/g, "\n");
  const rawLines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  // 展开纯 Base64 订阅
  const lines = expandBase64Lines(rawLines);

  const nodes = lines.map((line) => parseSingleLine(line));

  // 按客户端生成不同格式
  let body = "";
  if (
    client === "clash" ||
    client === "clash-meta" ||
    client === "clashmeta"
  ) {
    body = toClashYaml(nodes);
    return textResponse(body);
  }

  if (client === "surge") {
    body = toSurge(nodes);
    return textResponse(body);
  }

  if (client === "surfboard") {
    body = toSurfboard(nodes);
    return textResponse(body);
  }

  if (client === "loon") {
    body = toLoon(nodes);
    return textResponse(body);
  }

  if (client === "stash" || client === "mihomo" || client === "shadowrocket") {
    body = toClashJsonSs(nodes); // proxies: - {...}
    return textResponse(body);
  }

  if (client === "egern") {
    body = toEgern(nodes);
    return textResponse(body);
  }

  if (client === "quantumultx" || client === "quantumult-x") {
    body = toQuantumultX(nodes);
    return textResponse(body);
  }

  if (client === "sing-box" || client === "singbox") {
    body = toSingBox(nodes);
    return jsonResponseRaw(body);
  }

  if (client === "raw") {
    body = toRawUris(nodes);
    return textResponse(body);
  }

  if (client === "v2ray") {
    body = toBase64Subscription(nodes);
    return textResponse(body);
  }

  // 未识别 client：按你要求，返回 Base64 订阅
  body = toBase64Subscription(nodes);
  return textResponse(body);
}

/* ========== 公共工具 ========== */

function textResponse(body) {
  return new Response(body || "", {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
    },
  });
}

function jsonResponseRaw(objOrString) {
  const text =
    typeof objOrString === "string"
      ? objOrString
      : JSON.stringify(objOrString, null, 2);
  return new Response(text, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
  });
}

/* ========== Base64 展开 & 基础解析（和 node-parse 保持一致） ========== */

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
      if (decoded.includes("://")) {
        decoded
          .replace(/\r\n/g, "\n")
          .split("\n")
          .map((x) => x.trim())
          .filter((x) => x.length > 0)
          .forEach((x) => result.push(x));
        continue;
      } else {
        result.push(s);
      }
    } catch (e) {
      result.push(s);
    }
  }
  return result;
}

function isBase64Like(str) {
  if (!str || str.length < 8) return false;
  if (/[^A-Za-z0-9+/=_-]/.test(str)) return false;
  return true;
}

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
      // 其他协议先保留 raw
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

// 和 node-parse 的 parseVmess 一致
function parseVmess(line) {
  const full = line.slice("vmess://".length);
  let main = full;
  let query = "";

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
    const atIndex = decoded.lastIndexOf("@");
    if (atIndex !== -1) {
      const authPart = decoded.slice(0, atIndex);
      const hostPort = decoded.slice(atIndex + 1);

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
  const tlsFlag = security === "tls" || true;

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

function safeAtob(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad !== 0) s += "===";
  return atob(s);
}

function safeBtoa(str) {
  // 处理非 ASCII 字符
  return btoa(unescape(encodeURIComponent(str)));
}

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

/* ========== 各客户端生成逻辑：先完整支持 SS，其他协议优先走 Clash / Base64 ========== */

// Clash YAML（支持多协议，兼容 mihomo / clash meta / clash for android）
function toClashYaml(nodes) {
  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (!n.server || !n.port) continue;

    if (n.type === "vmess") {
      lines.push(...yamlVmess(n));
    } else if (n.type === "ss") {
      lines.push(...yamlSS(n));
    } else if (n.type === "vless") {
      lines.push(...yamlVless(n));
    } else if (n.type === "trojan") {
      lines.push(...yamlTrojan(n));
    } else {
      // 其他协议先不输出
    }
  }

  return lines.join("\n") + "\n";
}

function yamlVmess(n) {
  const out = [];
  const name = safeYamlString(n.name || "VMESS");
  const server = safeYamlString(n.server);
  const host = n.host ? safeYamlString(n.host) : null;
  const path = n.path ? safeYamlString(n.path) : "/";

  out.push(`  - name: "${name}"`);
  out.push(`    type: vmess`);
  out.push(`    server: ${server}`);
  out.push(`    port: ${n.port || 443}`);
  if (n.uuid) out.push(`    uuid: "${n.uuid}"`);
  out.push(`    alterId: 0`);
  out.push(`    cipher: ${n.cipher || "auto"}`);
  out.push(`    tls: ${n.tls ? "true" : "false"}`);

  if (n.network === "ws" || n.path || n.host) {
    out.push(`    network: ws`);
    out.push(`    ws-opts:`);
    out.push(`      path: "${path}"`);
    if (host) {
      out.push(`      headers:`);
      out.push(`        Host: "${host}"`);
    }
  }

  return out;
}

function yamlSS(n) {
  const out = [];
  const name = safeYamlString(n.name || "SS");
  const server = safeYamlString(n.server);

  out.push(`  - name: "${name}"`);
  out.push(`    type: ss`);
  out.push(`    server: ${server}`);
  out.push(`    port: ${n.port || 8388}`);
  if (n.cipher) out.push(`    cipher: ${n.cipher}`);
  if (n.password) out.push(`    password: "${safeYamlString(n.password)}"`);

  return out;
}

function yamlVless(n) {
  const out = [];
  const name = safeYamlString(n.name || "VLESS");
  const server = safeYamlString(n.server);
  const host = n.host ? safeYamlString(n.host) : null;
  const path = n.path ? safeYamlString(n.path) : "/";

  out.push(`  - name: "${name}"`);
  out.push(`    type: vless`);
  out.push(`    server: ${server}`);
  out.push(`    port: ${n.port || 443}`);
  if (n.uuid) out.push(`    uuid: "${n.uuid}"`);
  out.push(`    flow: ""`);
  out.push(`    udp: true`);
  out.push(`    tls: ${n.tls ? "true" : "false"}`);

  if (n.network === "ws" || n.path || n.host) {
    out.push(`    network: ws`);
    out.push(`    ws-opts:`);
    out.push(`      path: "${path}"`);
    if (host) {
      out.push(`      headers:`);
      out.push(`        Host: "${host}"`);
    }
  }

  return out;
}

function yamlTrojan(n) {
  const out = [];
  const name = safeYamlString(n.name || "TROJAN");
  const server = safeYamlString(n.server);

  out.push(`  - name: "${name}"`);
  out.push(`    type: trojan`);
  out.push(`    server: ${server}`);
  out.push(`    port: ${n.port || 443}`);
  if (n.password) out.push(`    password: "${safeYamlString(n.password)}"`);
  if (n.sni) out.push(`    sni: "${safeYamlString(n.sni)}"`);
  out.push(`    udp: true`);

  return out;
}

function safeYamlString(s) {
  if (s == null) return "";
  return String(s).replace(/"/g, '\\"');
}

/* ---- Surge ---- */

function toSurge(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    const name = n.name || "SS";
    lines.push(
      `${name}=ss,${n.server},${n.port},encrypt-method=${n.cipher},password="${n.password}"`
    );
  }
  return lines.join("\n");
}

/* ---- Surfboard ---- */

function toSurfboard(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    const name = n.name || "SS";
    lines.push(
      `${name}=ss,${n.server},${n.port},encrypt-method=${n.cipher},password=${n.password}`
    );
  }
  return lines.join("\n");
}

/* ---- Loon ---- */

function toLoon(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    const name = n.name || "SS";
    lines.push(
      `${name}=shadowsocks,${n.server},${n.port},${n.cipher},"${n.password}"`
    );
  }
  return lines.join("\n");
}

/* ---- Stash / Mihomo / Shadowrocket：JSON proxies ---- */

function toClashJsonSs(nodes) {
  const arr = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    arr.push({
      type: "ss",
      server: n.server,
      port: n.port,
      cipher: n.cipher,
      password: n.password,
      name: n.name || "SS",
    });
  }

  const lines = ["proxies:"];
  for (const item of arr) {
    lines.push("  - " + JSON.stringify(item));
  }
  return lines.join("\n");
}

/* ---- Egern ---- */

function toEgern(nodes) {
  const arr = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    arr.push({
      shadowsocks: {
        name: n.name || "SS",
        method: n.cipher,
        server: n.server,
        port: n.port,
        password: n.password,
      },
    });
  }
  const lines = ["proxies:"];
  for (const item of arr) {
    lines.push("  - " + JSON.stringify(item));
  }
  return lines.join("\n");
}

/* ---- Quantumult X ---- */

function toQuantumultX(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    const name = n.name || "SS";
    lines.push(
      `shadowsocks=${n.server}:${n.port},method=${n.cipher},password=${n.password},tag=${name}`
    );
  }
  return lines.join("\n");
}

/* ---- Sing-box ---- */

function toSingBox(nodes) {
  const outbounds = [];
  for (const n of nodes) {
    if (n.type !== "ss") continue;
    if (!n.server || !n.port || !n.cipher || !n.password) continue;
    outbounds.push({
      tag: n.name || "SS",
      type: "shadowsocks",
      server: n.server,
      server_port: n.port,
      method: n.cipher,
      password: n.password,
    });
  }
  return { outbounds };
}

/* ---- 原始 URI / Base64 订阅 ---- */

function toRawUris(nodes) {
  const lines = [];
  for (const n of nodes) {
    if (n.type === "others") continue;
    // SS 尽量补充成标准 ss://
    if (n.type === "ss" && n.server && n.port && n.cipher && n.password) {
      lines.push(buildSsUri(n));
    } else {
      lines.push(n.raw);
    }
  }
  return lines.join("\n");
}

function toBase64Subscription(nodes) {
  const content = toRawUris(nodes);
  return safeBtoa(content);
}

function buildSsUri(n) {
  const method = n.cipher || "aes-256-gcm";
  const pwd = n.password || "";
  const server = n.server || "127.0.0.1";
  const port = n.port || 8388;
  const payload = `${method}:${pwd}@${server}:${port}`;
  const b64 = safeBtoa(payload);
  const tag = n.name ? encodeURIComponent(n.name) : "";
  return `ss://${b64}${tag ? "#" + tag : ""}`;
}
