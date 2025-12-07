// functions/api/sub/Surge.js
//
// 支持类型输入：
// - URL 格式
// - URL / Base64 混合格式
// - Base64 单条 / 多条（整条订阅）
//
// 支持协议输出（仅支持白名单列表）：
// - Surge：
//      - Shadowsocks / UDP
//      - Shadowsocks / HTTP / UDP
//      - Trojan / UDP
//      - VMESS / UDP
//      - VMESS / Websocket / UDP
//      - Hysteria2 / UDP
//
// 已支持的客户端：
// - Surge（通过 /api/sub?client=surge 使用）
//
// 说明：
// - 本文件只处理 Surge 订阅：POST /api/sub/Surge，body 为原始节点文本。
// - 解析 + 白名单过滤都在本文件完成，Converter 只负责转发。

export async function onRequestPost(context) {
  const { request } = context;
  let text = (await request.text()) || "";
  text = text.trim();

  if (!text) {
    return new Response("# empty input\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 1) 尝试当成 Base64 订阅整段解码
  const compact = text.replace(/\s+/g, "");
  const decoded = safeBase64Decode(compact);
  if (
    decoded &&
    (decoded.includes("ss://") ||
      decoded.includes("trojan://") ||
      decoded.includes("vmess://") ||
      decoded.includes("hysteria2://") ||
      decoded.includes("vless://"))
  ) {
    text = decoded;
  }

  // 2) 从混合文本中提取所有 URL 形式的节点
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

// ================= 白名单形状：只下发这些 =================

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
    // 有 HTTP 混淆 → ss-http-udp，否则普通 ss-udp
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
    // vmess/http 不在 Surge 白名单里
    return "";
  }

  if (t === "hysteria2") {
    return "hysteria2-udp";
  }

  // 其它（vless 等）不下发
  return "";
}

// =============== 节点对象 → Surge 一行配置 ===============

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

  // ---- Shadowsocks / UDP & Shadowsocks / HTTP / UDP ----
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

  // ---- Trojan / UDP ----
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

  // ---- VMESS / UDP ----
  if (shape === "vmess-udp") {
    const uuid = n.uuid || "";

    return (
      `${tag}=vmess,${server},${port}` +
      `,username=${uuid}` +
      `,vmess-aead=true` +
      `,tls=false`
    );
  }

  // ---- VMESS / Websocket / UDP ----
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

  // ---- Hysteria2 / UDP ----
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

// =============== 从混合文本中提取并解析节点 ===============

function parseMixedNodesForSurge(text) {
  const nodes = [];
  const seen = new Set();

  const re =
    /(ss:\/\/[^\s#]+(?:#[^\s]*)?|trojan:\/\/[^\s#]+(?:#[^\s]*)?|vmess:\/\/[^\s#]+(?:#[^\s]*)?|hysteria2:\/\/[^\s#]+(?:#[^\s]*)?|vless:\/\/[^\s#]+(?:#[^\s]*)?)/gi;

  let m;
  while ((m = re.exec(text))) {
    const uri = m[0].trim();
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);

    const lower = uri.toLowerCase();
    let parsed = null;

    if (lower.startsWith("ss://")) {
      parsed = parseShadowsocks(uri);
    } else if (lower.startsWith("trojan://")) {
      parsed = parseTrojan(uri);
    } else if (lower.startsWith("vmess://")) {
      parsed = parseVmess(uri);
    } else if (lower.startsWith("hysteria2://")) {
      parsed = parseHysteria2(uri);
    } else if (lower.startsWith("vless://")) {
      // 可以解析出来给以后别的客户端用，但 Surge 白名单不会下发
      parsed = parseVless(uri);
    }

    if (parsed && parsed.type) {
      nodes.push(parsed);
    }
  }

  return nodes;
}

// =================== Shadowsocks 解析 ===================

function parseShadowsocks(uri) {
  try {
    let u = uri.replace(/^ss:\/\//i, "");

    // 备注（节点名）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.slice(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_e) {
        name = remarkPart;
      }
      u = u.slice(0, hashIndex);
    }

    // main + query
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    // userinfo@host:port
    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    let userinfo = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    // userinfo → method:password（可能是 Base64）
    const decodedUserinfo = safeBase64Decode(userinfo);
    if (decodedUserinfo && decodedUserinfo.includes(":")) {
      userinfo = decodedUserinfo;
    } else {
      try {
        userinfo = decodeURIComponent(userinfo);
      } catch (_e) {}
    }

    const colonIndex = userinfo.indexOf(":");
    if (colonIndex === -1) return null;

    const method = userinfo.slice(0, colonIndex);
    const password = userinfo.slice(colonIndex + 1);

    // host:port
    let host = hostPortNoPath || "0.0.0.0";
    let port = 8388;
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 8388;
      host = hostPortNoPath.slice(0, pm.index);
    }

    // 插件：obfs-local
    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

      // 直出的参数
      const qObfs = sp.get("obfs") || "";
      const qObfsHost = sp.get("obfs-host") || "";

      if (qObfs) pluginMode = qObfs;
      if (qObfsHost) {
        try {
          pluginHost = decodeURIComponent(qObfsHost);
        } catch (_e) {
          pluginHost = qObfsHost;
        }
      }

      // plugin=obfs-local;obfs=http;obfs-host=xxx
      const pluginParam = sp.get("plugin") || "";
      if (pluginParam) {
        const segs = pluginParam.split(";");
        for (const seg of segs) {
          const [k, v] = seg.split("=");
          if (!k || !v) continue;
          const kk = k.trim();
          let vv = v.trim();
          try {
            vv = decodeURIComponent(vv);
          } catch (_e) {}

          if (kk === "obfs") {
            pluginMode = vv;
          } else if (kk === "obfs-host") {
            pluginHost = vv;
          }
        }
      }

      if (pluginMode) {
        plugin = "obfs";
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
      cipher: method,
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

function parseTrojan(uri) {
  try {
    let u = uri.replace(/^trojan:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      try {
        name = decodeURIComponent(namePart);
      } catch (_e) {
        name = namePart;
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
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPortNoPath.slice(0, pm.index);
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
      if (peer) sni = peer;

      const allowInsecure = sp.get("allowInsecure") || "";
      if (allowInsecure === "1" || allowInsecure.toLowerCase() === "true") {
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

// =================== VLESS 解析（目前 Surge 白名单不下发） ===================

function parseVless(uri) {
  try {
    let u = uri.replace(/^vless:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      try {
        name = decodeURIComponent(namePart);
      } catch (_e) {
        name = namePart;
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
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPortNoPath.slice(0, pm.index);
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
      if (peer) sni = peer;

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

function parseVmess(uri) {
  try {
    let u = uri.replace(/^vmess:\/\//i, "");

    let full = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      full = u.slice(0, qIndex);
      queryStr = u.slice(qIndex + 1);
    }

    let main = full;

    // 尝试把 main 当 Base64 解码（auto:uuid@host:port 或 uuid@host:port）
    const decodedMain = safeBase64Decode(main);
    if (decodedMain && decodedMain.includes("@") && decodedMain.includes(":")) {
      main = decodedMain;
    }

    // 备注（# 后）
    let name = "";
    const hashIndex = main.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = main.slice(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_e) {
        name = remarkPart;
      }
      main = main.slice(0, hashIndex);
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    const userinfo = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    let host = hostPortNoPath || "0.0.0.0";
    let port = 443;
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPortNoPath.slice(0, pm.index);
    }

    // userinfo: auto:uuid 或 uuid
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

function parseHysteria2(uri) {
  try {
    let u = uri.replace(/^hysteria2:\/\//i, "");

    let name = "";
    let mainAndQuery = u;

    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const namePart = u.slice(hashIndex + 1);
      mainAndQuery = u.slice(0, hashIndex);
      try {
        name = decodeURIComponent(namePart);
      } catch (_e) {
        name = namePart;
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
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPortNoPath.slice(0, pm.index);
    }

    let sni = "";
    let portHopping = "";

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
    };
  } catch (_e) {
    return null;
  }
}

// =================== 工具函数 ===================

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