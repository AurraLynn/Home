// functions/api/sub/Surge.js
//
// 支持类型输入：
// -  URL 格式
// -  URL / Base64 混合
// -  Base64 单条 / 多条
//
// 支持协议输出（仅支持白名单列表）：
// -  Surge：
//      - Shadowsocks / UDP
//      - Shadowsocks / HTTP / UDP
//      - Trojan / UDP
//      - VMESS / UDP
//      - VMESS / Websocket / UDP
//      - Hysteria2 / UDP
//
// 已支持的客户端：
// - Surge
//
// 说明：
// - 本文件作为 /api/sub/Surge 的处理器：POST 请求 body 为原始节点文本，返回 Surge 一行一节点配置。
// - 解析与白名单过滤都在本文件完成，Converter 只负责转发。

export async function onRequestPost(context) {
  const { request } = context;
  const raw = (await request.text()) || "";
  let text = raw.trim();

  if (!text) {
    return new Response("# empty input\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const nodes = parseMixedNodesForSurge(text);
  if (!nodes.length) {
    return new Response("# no supported surge nodes\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const lines = [];
  for (const n of nodes) {
    const line = buildSurgeLineFromNode(n);
    if (line) lines.push(line);
  }

  if (!lines.length) {
    return new Response("# no supported surge nodes\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const out = lines.join("\n") + "\n";
  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// =================== 白名单形状：只下发这些类型 ===================

const SURGE_ALLOWED_SHAPES = new Set([
  "ss-udp",
  "ss-http-udp",
  "trojan-udp",
  "vmess-udp",
  "vmess-ws-udp",
  "hysteria2-udp",
]);

function getSurgeShape(node) {
  const t = (node.type || "").toLowerCase();

  if (t === "ss") {
    if (
      node.plugin === "obfs" &&
      (node.pluginMode || "").toLowerCase() === "http"
    ) {
      return "ss-http-udp";
    }
    return "ss-udp";
  }

  if (t === "trojan") {
    return "trojan-udp";
  }

  if (t === "vmess") {
    const obfs = (node.obfs || "").toLowerCase();
    if (!obfs) return "vmess-udp";
    if (obfs === "ws") return "vmess-ws-udp";
    // vmess / http 不在 Surge 白名单里，直接丢弃
    return "";
  }

  if (t === "hysteria2") {
    return "hysteria2-udp";
  }

  // Surge 暂不支持 vless 等其它类型（会被白名单过滤掉）
  return "";
}

// =================== 节点对象 → Surge 行 ===================

function buildSurgeLineFromNode(n) {
  if (!n || !n.type) return null;

  const shape = getSurgeShape(n);
  if (!SURGE_ALLOWED_SHAPES.has(shape)) return null;

  const name =
    n.name ||
    `${n.server || "0.0.0.0"}:${n.port != null ? n.port : "0"}`.trim() ||
    "unnamed";

  const tag = escapeComma(name);
  const server = n.server || "0.0.0.0";
  const port = n.port || 0;

  // ---------- Shadowsocks / UDP & Shadowsocks / HTTP / UDP ----------
  if (shape === "ss-udp" || shape === "ss-http-udp") {
    const cipher = n.cipher || "aes-128-gcm";
    const password = n.password || "";

    let line = `${tag}=ss,${server},${port},encrypt-method=${cipher},password="${escapeQuote(
      password
    )}"`;

    if (shape === "ss-http-udp" && n.plugin === "obfs") {
      line += `,obfs=http`;
      if (n.pluginHost) {
        line += `,obfs-host=${n.pluginHost}`;
      }
    }

    return line;
  }

  // ---------- Trojan / UDP ----------
  if (shape === "trojan-udp") {
    const password = n.password || "";
    const sni = n.sni || server;

    return (
      `${tag}=trojan,${server},${port}` +
      `,password="${escapeQuote(password)}"` +
      `,tls=true` +
      `,sni=${sni}` +
      `,skip-cert-verify=true`
    );
  }

  // ---------- VMESS / UDP ----------
  if (shape === "vmess-udp") {
    const uuid = n.uuid || "";

    return (
      `${tag}=vmess,${server},${port}` +
      `,username=${uuid}` +
      `,vmess-aead=true` +
      `,tls=false`
    );
  }

  // ---------- VMESS / WEBSOCKET / UDP ----------
  if (shape === "vmess-ws-udp") {
    const uuid = n.uuid || "";
    const wsHost = n.obfsHost || server;
    const wsPath = n.obfsUri || "/";

    return (
      `${tag}=vmess,${server},${port}` +
      `,username=${uuid}` +
      `,ws=true` +
      `,ws-path=${wsPath}` +
      `,ws-headers=Host:"${escapeQuote(wsHost)}"` +
      `,vmess-aead=true` +
      `,tls=false`
    );
  }

  // ---------- Hysteria2 / UDP ----------
  if (shape === "hysteria2-udp") {
    const password = n.password || "";
    const sni = n.sni || server;
    const portHopping = n.portHopping || "";

    let line = `${tag}=hysteria2,${server},${port},password="${escapeQuote(
      password
    )}"`;

    if (portHopping) {
      line += `,port-hopping="${escapeQuote(portHopping)}"`;
    }

    line += `,sni=${sni}`;
    line += `,skip-cert-verify=true`;
    line += `,tfo=false`;

    return line;
  }

  return null;
}

// =================== 解析整段文本：URL / Base64 / 混合 ===================

function parseMixedNodesForSurge(text) {
  let t = text || "";
  const nodes = [];

  // 尝试把整段当 Base64 订阅解码
  const compact = t.replace(/\s+/g, "");
  const decodedBulk = safeBase64Decode(compact);
  if (
    decodedBulk &&
    (decodedBulk.includes("ss://") ||
      decodedBulk.includes("trojan://") ||
      decodedBulk.includes("vmess://") ||
      decodedBulk.includes("hysteria2://") ||
      decodedBulk.includes("vless://"))
  ) {
    t = decodedBulk;
  }

  const re =
    /(ss:\/\/[\S]+|trojan:\/\/[\S]+|vmess:\/\/[\S]+|vless:\/\/[\S]+|hysteria2:\/\/[\S]+)/gi;

  const seenRaw = new Set();
  let m;
  while ((m = re.exec(t))) {
    const uri = m[0].trim();
    if (!uri || seenRaw.has(uri)) continue;
    seenRaw.add(uri);

    const lower = uri.toLowerCase();
    let parsed = null;

    if (lower.startsWith("ss://")) {
      parsed = parseShadowsocksLenient(uri);
    } else if (lower.startsWith("trojan://")) {
      parsed = parseTrojanLenient(uri);
    } else if (lower.startsWith("vmess://")) {
      parsed = parseVmessLenient(uri);
    } else if (lower.startsWith("hysteria2://")) {
      parsed = parseHysteria2Lenient(uri);
    } else if (lower.startsWith("vless://")) {
      parsed = parseVlessLenient(uri); // Surge 不下发，白名单会过滤掉
    }

    if (parsed && parsed.type) {
      nodes.push(parsed);
    }
  }

  return nodes;
}

// =================== Shadowsocks 解析（含 HTTP 混淆） ===================

function parseShadowsocksLenient(uri) {
  try {
    let u = uri.replace(/^ss:\/\//i, "");

    // 名称（# 之后）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      u = u.slice(0, hashIndex);
      if (namePart) {
        try {
          name = decodeURIComponent(namePart);
        } catch (_e) {
          name = namePart;
        }
      }
    }

    // main + query
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    let userinfo = "";
    let hostPortRaw = "";

    // 尝试 main 整段 Base64 解码
    const decodedMain = safeBase64Decode(main);
    if (decodedMain && decodedMain.includes("@") && decodedMain.includes(":")) {
      const atIdx = decodedMain.lastIndexOf("@");
      userinfo = decodedMain.slice(0, atIdx);
      hostPortRaw = decodedMain.slice(atIdx + 1);
    } else {
      const atIdx = main.lastIndexOf("@");
      if (atIdx === -1) return null;
      userinfo = main.slice(0, atIdx);
      hostPortRaw = main.slice(atIdx + 1);
    }

    // userinfo: 可能是 cipher:password / base64(cipher):password / base64("cipher:password")
    let cipher = "";
    let password = "";

    if (userinfo.includes(":")) {
      const lastColon = userinfo.lastIndexOf(":");
      const cipherPart = userinfo.slice(0, lastColon);
      const passPart = userinfo.slice(lastColon + 1);

      const decodedCipher = safeBase64Decode(cipherPart);
      if (decodedCipher && !decodedCipher.includes("@") && decodedCipher.includes("-")) {
        cipher = decodedCipher;
      } else {
        cipher = cipherPart;
      }

      password = passPart;
    } else {
      const decUi = safeBase64Decode(userinfo);
      if (decUi && decUi.includes(":")) {
        const lastColon2 = decUi.lastIndexOf(":");
        cipher = decUi.slice(0, lastColon2);
        password = decUi.slice(lastColon2 + 1);
      }
    }

    // host:port
    let host = hostPortRaw;
    let port = 8388;
    const m = hostPortRaw.match(/:(\d+)$/);
    if (m) {
      port = parseInt(m[1], 10) || 8388;
      host = hostPortRaw.slice(0, m.index);
    }

    // 插件（obfs-local）
    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);
      const pluginParam = sp.get("plugin") || "";

      if (pluginParam && pluginParam.includes("obfs-local")) {
        plugin = "obfs";

        pluginMode = sp.get("obfs") || "";
        let ph = sp.get("obfs-host") || "";
        if (ph) {
          try {
            ph = decodeURIComponent(ph);
          } catch (_e) {}
        }
        pluginHost = ph;

        if (!pluginMode) {
          const mm = pluginParam.match(/obfs=([^;]+)/);
          if (mm) pluginMode = mm[1];
        }
        if (!pluginHost) {
          const mh = pluginParam.match(/obfs-host=([^;]+)/);
          if (mh) {
            let v = mh[1];
            try {
              v = decodeURIComponent(v);
            } catch (_e) {}
            pluginHost = v;
          }
        }
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      scheme: "ss",
      type: "ss",
      name,
      server: host,
      port,
      cipher,
      password,
      plugin,
      pluginMode,
      pluginHost,
    };
  } catch (_e) {
    return null;
  }
}

// =================== Trojan 解析 ===================

function parseTrojanLenient(uri) {
  try {
    let u = uri.replace(/^trojan:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      if (namePart) {
        try {
          name = decodeURIComponent(namePart);
        } catch (_e) {
          name = namePart;
        }
      }
    }

    let main = mainAndQuery;
    let queryStr = "";
    const qIndex = mainAndQuery.indexOf("?");
    if (qIndex !== -1) {
      main = mainAndQuery.slice(0, qIndex);
      queryStr = mainAndQuery.slice(qIndex + 1);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const passwordPart = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    let password = "";
    try {
      password = decodeURIComponent(passwordPart);
    } catch (_e) {
      password = passwordPart;
    }

    let host = hostPortNoPath || "0.0.0.0";
    let port = 443;
    const m = hostPortNoPath.match(/:(\d+)$/);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPortNoPath.slice(0, m.index);
    }

    let sni = "";
    let skipCertVerify = false;

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

      const r =
        sp.get("remarks") ||
        sp.get("name") ||
        sp.get("tag") ||
        sp.get("remark") ||
        "";
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }

      const peer = sp.get("peer") || sp.get("sni") || "";
      if (peer) {
        sni = peer;
      }

      const insecure = sp.get("allowInsecure") || "";
      if (insecure === "1" || insecure.toLowerCase() === "true") {
        skipCertVerify = true;
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      scheme: "trojan",
      type: "trojan",
      name,
      server: host,
      port,
      password,
      sni,
      skipCertVerify,
    };
  } catch (_e) {
    return null;
  }
}

// =================== VLESS 解析（Surge 不用，仅保留结构） ===================

function parseVlessLenient(uri) {
  try {
    let u = uri.replace(/^vless:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      if (namePart) {
        try {
          name = decodeURIComponent(namePart);
        } catch (_e) {
          name = namePart;
        }
      }
    }

    let main = mainAndQuery;
    let queryStr = "";
    const qIndex = mainAndQuery.indexOf("?");
    if (qIndex !== -1) {
      main = mainAndQuery.slice(0, qIndex);
      queryStr = mainAndQuery.slice(qIndex + 1);
    }

    if (!main.includes("@")) {
      const dec = safeBase64Decode(main);
      if (dec && dec.includes("@")) {
        main = dec;
      }
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    let host = hostPortNoPath || "0.0.0.0";
    let port = 443;
    const m = hostPortNoPath.match(/:(\d+)$/);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPortNoPath.slice(0, m.index);
    }

    let uuid = "";
    if (userinfo.includes(":")) {
      const parts = userinfo.split(":");
      uuid = parts[parts.length - 1] || "";
    } else {
      uuid = userinfo;
    }

    let tls = "";
    let sni = "";
    let path = "";

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

      const r =
        sp.get("remarks") ||
        sp.get("name") ||
        sp.get("tag") ||
        sp.get("remark") ||
        "";
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }

      const tlsFlag = sp.get("tls") || sp.get("security") || "";
      if (tlsFlag === "1" || tlsFlag.toLowerCase() === "tls") {
        tls = "tls";
      }

      const peer = sp.get("peer") || sp.get("sni") || "";
      if (peer) {
        sni = peer;
      }

      const p = sp.get("path") || "";
      if (p) path = p;
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      scheme: "vless",
      type: "vless",
      name,
      server: host,
      port,
      uuid,
      encryption: "none",
      tls,
      sni,
      path,
    };
  } catch (_e) {
    return null;
  }
}

// =================== VMESS 解析 ===================

function parseVmessLenient(uri) {
  try {
    let u = uri.replace(/^vmess:\/\//i, "");

    let mainAndQuery = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      mainAndQuery = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    let main = mainAndQuery;

    const decodedMain = safeBase64Decode(main);
    if (
      decodedMain &&
      decodedMain.includes("@") &&
      decodedMain.includes(":")
    ) {
      main = decodedMain;
    }

    let name = "";
    const hashIndex = main.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = main.slice(hashIndex + 1);
      main = main.slice(0, hashIndex);
      if (namePart) {
        try {
          name = decodeURIComponent(namePart);
        } catch (_e) {
          name = namePart;
        }
      }
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    let host = hostPortNoPath || "0.0.0.0";
    let port = 443;
    const m = hostPortNoPath.match(/:(\d+)$/);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPortNoPath.slice(0, m.index);
    }

    let uuid = "";
    if (userinfo.includes(":")) {
      const parts = userinfo.split(":");
      uuid = parts[parts.length - 1] || "";
    } else {
      uuid = userinfo;
    }

    let obfs = "";
    let obfsHost = "";
    let obfsUri = "/";
    let tls = "";

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

      const r =
        sp.get("remarks") ||
        sp.get("name") ||
        sp.get("tag") ||
        sp.get("remark") ||
        "";
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }

      const obfsType = sp.get("obfs") || sp.get("network") || "";
      const hostFrom = sp.get("obfsParam") || sp.get("host") || "";
      const path = sp.get("path") || sp.get("obfsUri") || "";

      if (obfsType === "websocket" || obfsType === "ws") {
        obfs = "ws";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      } else if (obfsType === "http") {
        obfs = "http";
        obfsHost = hostFrom || host;
        obfsUri = path || "/";
      }

      const tlsFlag = sp.get("tls") || sp.get("security") || "";
      if (tlsFlag === "1" || tlsFlag.toLowerCase() === "tls") {
        tls = "tls";
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      scheme: "vmess",
      type: "vmess",
      name,
      server: host,
      port,
      uuid,
      encryption: "auto",
      obfs,
      obfsHost,
      obfsUri,
      tls,
    };
  } catch (_e) {
    return null;
  }
}

// =================== Hysteria2 解析 ===================

function parseHysteria2Lenient(uri) {
  try {
    let u = uri.replace(/^hysteria2:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      if (namePart) {
        try {
          name = decodeURIComponent(namePart);
        } catch (_e) {
          name = namePart;
        }
      }
    }

    let main = mainAndQuery;
    let queryStr = "";
    const qIndex = mainAndQuery.indexOf("?");
    if (qIndex !== -1) {
      main = mainAndQuery.slice(0, qIndex);
      queryStr = mainAndQuery.slice(qIndex + 1);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const passwordPart = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    let password = "";
    try {
      password = decodeURIComponent(passwordPart);
    } catch (_e) {
      password = passwordPart;
    }

    let host = hostPortNoPath || "0.0.0.0";
    let port = 443;
    const m = hostPortNoPath.match(/:(\d+)$/);
    if (m) {
      port = parseInt(m[1], 10) || 443;
      host = hostPortNoPath.slice(0, m.index);
    }

    let sni = "";
    let portHopping = "";
    let skipCertVerify = false;

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

      const r =
        sp.get("remarks") ||
        sp.get("name") ||
        sp.get("tag") ||
        sp.get("remark") ||
        "";
      if (r) {
        try {
          name = decodeURIComponent(r);
        } catch (_e) {
          name = r;
        }
      }

      const sniVal = sp.get("peer") || sp.get("sni") || "";
      if (sniVal) sni = sniVal;

      const mp = sp.get("mport") || sp.get("port-hopping") || "";
      if (mp) portHopping = mp;

      const insecure = sp.get("insecure") || "";
      if (insecure === "1" || insecure.toLowerCase() === "true") {
        skipCertVerify = true;
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      scheme: "hysteria2",
      type: "hysteria2",
      name,
      server: host,
      port,
      password,
      sni,
      portHopping,
      skipCertVerify,
    };
  } catch (_e) {
    return null;
  }
}

// =================== 基础工具 ===================

function safeBase64Decode(str) {
  if (!str) return "";
  let s = str.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad === 2) s += "==";
  else if (pad === 3) s += "=";
  else if (pad === 1) return "";

  try {
    const bin = atob(s);
    try {
      return decodeURIComponent(
        Array.prototype
          .map.call(bin, (c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
    } catch (_e) {
      return bin;
    }
  } catch (_e) {
    return "";
  }
}

function escapeComma(str) {
  if (!str) return "";
  return String(str).replace(/,/g, "，");
}

function escapeQuote(str) {
  if (!str) return "";
  return String(str).replace(/"/g, '\\"');
}