// functions/api/node-convert.js
// 节点识别 + 转换接口
// POST /api/node-convert?client=clash
// Body: 纯文本，多行节点

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
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const nodes = lines.map((line) => parseSingleLine(line));

  // Clash 系（Clash / Meta / Mihomo / Sing-box 基本都能吃）
  if (
    client === "clash" ||
    client === "clash-meta" ||
    client === "mihomo" ||
    client === "sing-box" ||
    client === "clashmeta"
  ) {
    const yaml = toClashYaml(nodes);
    return new Response(yaml, {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  }

  // 返回标准化后的原始 URI（做“通用订阅”用）
  if (client === "raw") {
    const content = nodes
      .filter((n) => n.type !== "others")
      .map((n) => n.raw)
      .join("\n");
    return new Response(content, {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  }

  return new Response(
    `暂未实现客户端类型: ${client}。目前支持: clash / clash-meta / mihomo / sing-box / raw`,
    { status: 400 }
  );
}

/* ===================== 公共解析逻辑（与 node-parse 保持一致） ===================== */

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
      // 其他协议后面扩展
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

// 和 node-parse.js 保持同一版 parseVmess
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

/* ===================== 转 Clash YAML ===================== */

function toClashYaml(nodes) {
  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (!n.server || !n.port) {
      continue;
    }

    if (n.type === "vmess") {
      lines.push(...yamlVmess(n));
    } else if (n.type === "ss") {
      lines.push(...yamlSS(n));
    } else if (n.type === "vless") {
      lines.push(...yamlVless(n));
    } else if (n.type === "trojan") {
      lines.push(...yamlTrojan(n));
    } else {
      // 其他协议先忽略
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
