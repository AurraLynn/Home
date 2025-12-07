// functions/api/sub/Clash.js
//
// 支持输入：
// -  URL 格式
// -  URL / Base64 混合格式
// -  Base64（单条、多条）
//
// 支持输出（仅支持白名单列表）：
// -  Clash / Mihomo：
//         Shadowsocks / UDP
//         Shadowsocks / HTTP / UDP
//         TROJAN / UDP
//         Hysteria2 / UDP

export async function onRequestPost(context) {
  const { request } = context;
  let text = (await request.text()) || "";
  text = text.trim();

  if (!text) {
    return new Response("# no nodes", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 尝试整体按订阅 Base64 解一层
  const compact = text.replace(/\s+/g, "");
  const decodedWhole = safeBase64Decode(compact);
  if (decodedWhole && decodedWhole.includes("ss://")) {
    text = decodedWhole;
  }

  const nodes = parseWhitelistNodes(text);

  if (!nodes.length) {
    return new Response("# no nodes", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const lines = [];
  lines.push("proxies:");

  for (const n of nodes) {
    if (n.type === "ss") {
      const obj = {
        type: "ss",
        server: n.server,
        port: n.port,
        cipher: n.cipher,
        password: n.password,
        name: n.name,
      };

      if ((n.plugin || "").toLowerCase() === "obfs" && n.pluginMode) {
        obj.plugin = "obfs";
        const opts = { mode: n.pluginMode };
        if (n.pluginHost) {
          opts.host = n.pluginHost;
        }
        obj["plugin-opts"] = opts;
      }

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "trojan") {
      const obj = {
        type: "trojan",
        server: n.server,
        port: n.port,
        password: n.password,
        sni: n.sni || n.server,
        "skip-cert-verify": n.skipCertVerify === true,
        name: n.name,
      };
      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "hysteria2") {
      const obj = {
        type: "hysteria2",
        server: n.server,
        port: n.port,
        auth: n.auth,             // password
        sni: n.sni || "",
        "skip-cert-verify": n.skipCertVerify === true,
        "fast-open": false,
        name: n.name,
      };
      if (n.ports) {
        obj.ports = n.ports;      // 例如 "35000-39000"
      }
      lines.push("  - " + JSON.stringify(obj));
    }
  }

  return new Response(lines.join("\n") + "\n", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ================= 白名单解析层 ================= */

function parseWhitelistNodes(text) {
  const nodes = [];
  const seen = new Set();

  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line) continue;

    // 行里如果有空格，只取第一个片段
    const firstToken = line.split(/\s+/)[0];

    const lower = firstToken.toLowerCase();

    // 只处理三种前缀，其它行全部忽略
    if (lower.startsWith("ss://")) {
      const uri = firstToken;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseShadowsocks(uri);
      if (!n) continue;

      const shape = getSsShape(n);
      if (shape !== "ss-udp" && shape !== "ss-http-udp") continue; // 白名单

      nodes.push(n);
    } else if (lower.startsWith("trojan://")) {
      const uri = firstToken;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseTrojan(uri);
      if (!n) continue;
      // trojan / udp：所有 trojan 节点都视为支持 udp
      nodes.push(n);
    } else if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
      const uri = firstToken;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseHysteria2(uri);
      if (!n) continue;
      // hy2 / udp：所有 hysteria2 节点都视为支持 udp
      nodes.push(n);
    }
  }

  return nodes;
}

/* ================= Shadowsocks 解析：ss:// ================= */

function getSsShape(n) {
  const plugin = (n.plugin || "").toLowerCase();
  const mode = (n.pluginMode || "").toLowerCase();

  if (plugin === "obfs" && mode === "http") {
    return "ss-http-udp";
  }
  return "ss-udp";
}

function parseShadowsocks(uri) {
  try {
    if (!uri.toLowerCase().startsWith("ss://")) return null;

    let u = uri.replace(/^ss:\/\//i, "");

    // 节点名
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.substring(hashIndex + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIndex);
    }

    // main + query
    let main = u;
    let queryStr = "";
    const qIndex = u.indexOf("?");
    if (qIndex !== -1) {
      main = u.substring(0, qIndex);
      queryStr = u.substring(qIndex + 1);
    }

    // main 可能是 Base64(method:password@host:port)
    const decodedMain = safeBase64Decode(main);
    if (decodedMain && decodedMain.includes("@") && decodedMain.includes(":")) {
      main = decodedMain;
    }

    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    let userinfo = main.substring(0, atIndex);
    const hostPortRaw = main.substring(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    // userinfo 也可能是 Base64(method:password)
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

    const method = userinfo.substring(0, colonIndex);
    const password = userinfo.substring(colonIndex + 1);

    let host = hostPortNoPath || "0.0.0.0";
    let port = 8388;
    const pm = hostPortNoPath.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 8388;
      host = hostPortNoPath.substring(0, pm.index);
    }

    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const qObfs = search.get("obfs") || "";
      const qObfsHost = search.get("obfs-host") || "";
      if (qObfs) pluginMode = qObfs;
      if (qObfsHost) {
        try {
          pluginHost = decodeURIComponent(qObfsHost);
        } catch (_e) {
          pluginHost = qObfsHost;
        }
      }

      const pluginParam = search.get("plugin") || "";
      if (pluginParam) {
        const segs = pluginParam.split(";");
        for (const seg of segs) {
          const [kRaw, vRaw] = seg.split("=");
          if (!kRaw || typeof vRaw === "undefined") continue;
          const k = kRaw.trim();
          let v = vRaw.trim();
          try {
            v = decodeURIComponent(v);
          } catch (_e) {}

          if (k === "obfs") pluginMode = v;
          else if (k === "obfs-host") pluginHost = v;
        }
      }

      if (pluginMode) plugin = "obfs";
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      type: "ss",
      server: host,
      port,
      cipher: method,
      password,
      plugin,
      pluginMode,
      pluginHost,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= Trojan 解析：trojan:// ================= */

function parseTrojan(uri) {
  try {
    if (!uri.toLowerCase().startsWith("trojan://")) return null;

    let u = uri.replace(/^trojan:\/\//i, "");

    // 节点名
    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    // main + query
    let main = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      main = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    // password@host:port
    const atIdx = main.lastIndexOf("@");
    if (atIdx === -1) return null;
    let password = main.substring(0, atIdx);
    const hostPort = main.substring(atIdx + 1);

    try {
      password = decodeURIComponent(password);
    } catch (_e) {}

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let sni = host;
    let skipCertVerify = false;

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const peer = search.get("peer");
      if (peer) {
        try {
          sni = decodeURIComponent(peer);
        } catch (_e) {
          sni = peer;
        }
      }

      const allowInsecure = (search.get("allowInsecure") || "").toLowerCase();
      if (allowInsecure === "1" || allowInsecure === "true") {
        skipCertVerify = true;
      }
    }

    if (!name) name = `${host}:${port}`;

    return {
      raw: uri,
      type: "trojan",
      server: host,
      port,
      password,
      sni,
      skipCertVerify,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= Hysteria2 解析：hysteria2:// / hy2:// ================= */

function parseHysteria2(uri) {
  try {
    let lower = uri.toLowerCase();
    if (!lower.startsWith("hysteria2://") && !lower.startsWith("hy2://")) {
      return null;
    }

    let u = uri.replace(/^hysteria2:\/\//i, "").replace(/^hy2:\/\//i, "");

    // main + query(+备注)
    const qIdx = u.indexOf("?");
    if (qIdx === -1) return null;

    const main = u.substring(0, qIdx);
    const rest = u.substring(qIdx + 1);

    // rest 可能是 "peer=..&insecure=1&mport=35000-39000%23%25F0..." 这种
    let queryStr = rest;
    let name = "";

    const encodedSharpIdx = rest.indexOf("%23"); // %23 = '#'
    if (encodedSharpIdx !== -1) {
      queryStr = rest.substring(0, encodedSharpIdx);
      const remarkEnc = rest.substring(encodedSharpIdx + 3); // 跳过 "%23"
      name = decodeNameMaybeTwice(remarkEnc);
    }

    // auth@host:port
    const atIdx = main.lastIndexOf("@");
    if (atIdx === -1) return null;
    let auth = main.substring(0, atIdx);
    const hostPort = main.substring(atIdx + 1);

    try {
      auth = decodeURIComponent(auth);
    } catch (_e) {}

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let sni = "";
    let skipCertVerify = false;
    let ports = "";

    if (queryStr) {
      const search = new URLSearchParams(queryStr);

      const peer = search.get("peer");
      if (peer) {
        try {
          sni = decodeURIComponent(peer);
        } catch (_e) {
          sni = peer;
        }
      }

      const insecure = (search.get("insecure") || "").toLowerCase();
      if (insecure === "1" || insecure === "true") {
        skipCertVerify = true;
      }

      const mport = search.get("mport") || search.get("ports");
      if (mport) {
        try {
          ports = decodeURIComponent(mport);
        } catch (_e) {
          ports = mport;
        }
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      type: "hysteria2",
      server: host,
      port,
      auth,
      sni,
      skipCertVerify,
      ports,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= 工具 ================= */

function decodeNameMaybeTwice(str) {
  let s = str || "";
  // 第一次解码（从 %25F0.. 变成 %F0..）
  try {
    if (s.includes("%")) s = decodeURIComponent(s);
  } catch (_e) {}
  // 第二次解码（从 %F0.. 变成 emoji/中文）
  try {
    if (s.includes("%")) s = decodeURIComponent(s);
  } catch (_e) {}
  return s;
}

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
        Array.prototype.map
          .call(bin, (c) => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
    } catch (_e) {
      return bin;
    }
  } catch (_e) {
    return "";
  }
}
