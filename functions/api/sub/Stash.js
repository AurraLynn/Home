// functions/api/sub/Stash.js
//
// 支持输入：
// - URL 格式
// - URL / Base64 混合格式
// - Base64 单条 / 多条（整条订阅）
//
// 支持协议输出（仅支持白名单列表）(不套配置模版)：
// - Stash：
//      - Shadowsocks / UDP
//      - Shadowsocks / HTTP / UDP
//

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

  // 尝试把整个当订阅 Base64 解一层
  const compact = text.replace(/\s+/g, "");
  const decodedWhole = safeBase64Decode(compact);
  if (
    decodedWhole &&
    (decodedWhole.includes("ss://") ||
      decodedWhole.includes("vmess://") ||
      decodedWhole.includes("vless://") ||
      decodedWhole.includes("trojan://") ||
      decodedWhole.includes("hysteria2://") ||
      decodedWhole.includes("hy2://"))
  ) {
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
      // Shadowsocks
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
        const opts = { mode: n.pluginMode }; // http / tls
        if (n.pluginHost) {
          opts.host = n.pluginHost;
        }
        obj["plugin-opts"] = opts;
      }

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "trojan") {
      // Trojan
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
      // Hysteria2（按你给的 password + tfo 格式）
      const obj = {
        type: "hysteria2",
        name: n.name,
        server: n.server,
        port: n.port,
        "skip-cert-verify": n.skipCertVerify === true,
        tfo: !n.ports, // 有 ports 就认为关闭 tfo
        password: n.auth,
      };
      if (n.ports) obj.ports = n.ports;
      if (n.sni) obj.sni = n.sni;

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "vmess") {
      // VMess
      const obj = {
        name: n.name,
        type: "vmess",
        server: n.server,
        port: n.port,
        cipher: n.cipher || "auto",
        uuid: n.uuid,
        alterId: typeof n.alterId === "number" ? n.alterId : 0,
        tls: !!n.tls,
      };

      if (n.network === "http") {
        obj.network = "http";
        obj["http-opts"] = {
          path: [n.path || "/"],
          headers: {
            Host: [n.hostHeader || n.server],
          },
        };
      } else if (n.network === "ws") {
        obj.network = "ws";
        obj["ws-opts"] = {
          path: n.path || "/",
          headers: {
            Host: n.hostHeader || n.server,
          },
        };
      }

      lines.push("  - " + JSON.stringify(obj));
    } else if (n.type === "vless") {
      // VLESS（Reality / XTLS / WS）
      const obj = {
        type: "vless",
        name: n.name,
        server: n.server,
        port: n.port,
        uuid: n.uuid,
        tls: !!n.tls,
        "skip-cert-verify": n.skipCertVerify === true,
        network: n.network || "tcp",
      };

      if (n.servername) {
        obj.servername = n.servername;
      }

      // Reality
      if (n.pbk) {
        obj["reality-opts"] = {
          "public-key": n.pbk,
        };
        if (n.sid) {
          obj["reality-opts"]["short-id"] = n.sid;
        }
      }

      // xtls-rprx-vision
      if (n.flow === "xtls-rprx-vision") {
        obj.flow = "xtls-rprx-vision";
      }

      // WebSocket
      if (obj.network === "ws") {
        obj["ws-opts"] = {
          path: n.path || "/",
          headers: {
            Host: n.hostHeader || n.servername || n.server,
          },
        };
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

    // 一行里如果有空格，只取第一个片段
    let token = line.split(/\s+/)[0];
    if (!token) continue;

    // 有些会整行再 urlencode 一次，这里先尝试解一层
    try {
      const decodedOnce = decodeURIComponent(token);
      if (
        decodedOnce.startsWith("ss://") ||
        decodedOnce.startsWith("trojan://") ||
        decodedOnce.startsWith("hysteria2://") ||
        decodedOnce.startsWith("hy2://") ||
        decodedOnce.startsWith("vmess://") ||
        decodedOnce.startsWith("vless://")
      ) {
        token = decodedOnce;
      }
    } catch (_e) {}

    const lower = token.toLowerCase();

    if (lower.startsWith("ss://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseShadowsocks(uri);
      if (!n) continue;

      const shape = getSsShape(n);
      if (shape !== "ss-udp" && shape !== "ss-http-udp") continue;

      nodes.push(n);
    } else if (lower.startsWith("trojan://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseTrojan(uri);
      if (!n) continue;
      nodes.push(n);
    } else if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseHysteria2(uri);
      if (!n) continue;
      nodes.push(n);
    } else if (lower.startsWith("vmess://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseVMess(uri);
      if (!n) continue;

      const shape = getVmessShape(n);
      if (
        shape !== "vmess-udp" &&
        shape !== "vmess-http-udp" &&
        shape !== "vmess-ws-udp"
      ) {
        continue;
      }

      nodes.push(n);
    } else if (lower.startsWith("vless://")) {
      const uri = token;
      if (seen.has(uri)) continue;
      seen.add(uri);

      const n = parseVless(uri);
      if (!n) continue;

      // vless/udp, vless/xtls-rprx-vision/udp, vless/websocket/udp
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

    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    let main = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      main = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    const atIdx = main.lastIndexOf("@");
    if (atIdx === -1) return null;
    const password = main.substring(0, atIdx); // 保持原样
    const hostPort = main.substring(atIdx + 1);

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
    let s = uri.trim();

    // 可能整条再 encode 一次，先尝试解一层
    try {
      const d1 = decodeURIComponent(s);
      if (d1.startsWith("hysteria2://") || d1.startsWith("hy2://")) {
        s = d1;
      }
    } catch (_e) {}

    let lower = s.toLowerCase();
    if (!lower.startsWith("hysteria2://") && !lower.startsWith("hy2://")) {
      return null;
    }

    let u = s.replace(/^hysteria2:\/\//i, "").replace(/^hy2:\/\//i, "");

    let name = "";
    const hashIdx = u.indexOf("#");
    if (hashIdx !== -1) {
      const remarkPart = u.substring(hashIdx + 1);
      name = decodeNameMaybeTwice(remarkPart);
      u = u.substring(0, hashIdx);
    }

    const qIdx = u.indexOf("?");
    if (qIdx === -1) return null;
    const main = u.substring(0, qIdx);
    const queryStr = u.substring(qIdx + 1);

    const atIdx = main.lastIndexOf("@");
    if (atIdx === -1) return null;
    const auth = main.substring(0, atIdx);
    const hostPort = main.substring(atIdx + 1);

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

/* ================= VMess 解析：vmess://（URL 形态） ================= */

function getVmessShape(n) {
  if (n.network === "http") return "vmess-http-udp";
  if (n.network === "ws") return "vmess-ws-udp";
  return "vmess-udp";
}

function parseVMess(uri) {
  try {
    if (!uri.toLowerCase().startsWith("vmess://")) return null;

    let u = uri.replace(/^vmess:\/\//i, "");
    u = u.replace(/\s+$/g, ""); // 去掉末尾空白

    let name = "";

    let mainPart = u;
    let queryStr = "";
    const qIdx = u.indexOf("?");
    if (qIdx !== -1) {
      mainPart = u.substring(0, qIdx);
      queryStr = u.substring(qIdx + 1);
    }

    // main 是 Base64(auth:uuid@host:port)
    const decodedMain = safeBase64Decode(mainPart);
    if (!decodedMain || !decodedMain.includes("@")) return null;

    const atIdx = decodedMain.lastIndexOf("@");
    if (atIdx === -1) return null;

    const userinfo = decodedMain.substring(0, atIdx); // 例如 auto:UUID
    const hostPort = decodedMain.substring(atIdx + 1);

    const colonIdx = userinfo.indexOf(":");
    let cipher = "auto";
    let uuid = "";
    if (colonIdx !== -1) {
      cipher = userinfo.substring(0, colonIdx) || "auto";
      uuid = userinfo.substring(colonIdx + 1);
    } else {
      uuid = userinfo;
    }

    let host = hostPort || "0.0.0.0";
    let port = 443;
    const pm = hostPort.match(/:(\d+)$/);
    if (pm) {
      port = parseInt(pm[1], 10) || 443;
      host = hostPort.substring(0, pm.index);
    }

    let network = "tcp"; // http / ws
    let path = "/";
    let hostHeader = "";
    let tls = false;
    let alterId = 0;

    if (queryStr) {
      const qs = new URLSearchParams(queryStr);

      const remarks = qs.get("remarks");
      if (remarks) {
        name = decodeNameMaybeTwice(remarks);
      }

      const obfs = (qs.get("obfs") || "").toLowerCase();
      const obfsParam = qs.get("obfsParam") || qs.get("host") || "";
      const pathParam = qs.get("path");

      if (obfs === "http") {
        network = "http";
      } else if (obfs === "websocket") {
        network = "ws";
      } else {
        network = "tcp";
      }

      if (pathParam) {
        try {
          path = decodeURIComponent(pathParam) || "/";
        } catch (_e) {
          path = pathParam || "/";
        }
      }

      if (obfsParam) {
        try {
          hostHeader = decodeURIComponent(obfsParam);
        } catch (_e) {
          hostHeader = obfsParam;
        }
      }

      const tlsParam = (qs.get("tls") || "").toLowerCase();
      if (tlsParam === "1" || tlsParam === "true") {
        tls = true;
      }

      const aid = qs.get("alterId");
      if (aid && !Number.isNaN(parseInt(aid, 10))) {
        alterId = parseInt(aid, 10);
      }
    }

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      type: "vmess",
      server: host,
      port,
      cipher,
      uuid,
      alterId,
      tls,
      network,
      path,
      hostHeader,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= VLESS 解析：vless:// ================= */

function parseVless(uri) {
  try {
    let raw = uri.trim();

    // 有可能整条被 encode 一次
    try {
      const d1 = decodeURIComponent(raw);
      if (d1.startsWith("vless://")) {
        raw = d1;
      }
    } catch (_e) {}

    if (!raw.toLowerCase().startsWith("vless://")) return null;

    // 去掉 scheme
    let s = raw.replace(/^vless:\/\//i, "");

    // 先剥掉 fragment
    let fragment = "";
    const hashIdx = s.indexOf("#");
    if (hashIdx !== -1) {
      fragment = s.substring(hashIdx + 1);
      s = s.substring(0, hashIdx);
    }

    // 再拆 query
    let main = s;
    let queryStr = "";
    const qIdx = s.indexOf("?");
    if (qIdx !== -1) {
      main = s.substring(0, qIdx);
      queryStr = s.substring(qIdx + 1);
    }

    const params = new URLSearchParams(queryStr);

    // 备注：优先 ?remarks=，其次 #fragment
    let name = params.get("remarks") || "";
    if (!name && fragment) {
      name = fragment;
    }
    if (name) {
      name = decodeNameMaybeTwice(name);
    }

    // ========== 解析 main，提取 uuid / host / port ==========
    let host = "0.0.0.0";
    let port = 443;
    let uuid = "";

    if (main.includes("@")) {
      // 形态：userinfo@host:port
      const atIdx = main.lastIndexOf("@");
      const userinfoRaw = main.substring(0, atIdx);
      const hostPortRaw = main.substring(atIdx + 1);

      let userinfoDecoded = safeBase64Decode(userinfoRaw);
      let userinfo = userinfoDecoded || userinfoRaw;

      // userinfo 可能是 auto:uuid 或 直接 uuid
      const colonIdx = userinfo.indexOf(":");
      if (colonIdx !== -1) {
        uuid = userinfo.substring(colonIdx + 1);
      } else {
        uuid = userinfo;
      }

      let hp = hostPortRaw;
      const m = hp.match(/:(\d+)$/);
      if (m) {
        port = parseInt(m[1], 10) || 443;
        host = hp.substring(0, m.index);
      } else {
        host = hp || host;
      }
    } else {
      // 形态可能是：
      // 1) BASE64(auto:uuid@host:port)
      // 2) host[:port]
      const decoded = safeBase64Decode(main);
      if (decoded && decoded.includes("@")) {
        const atIdx = decoded.lastIndexOf("@");
        const userinfo = decoded.substring(0, atIdx);
        const hostPortRaw = decoded.substring(atIdx + 1);

        const colonIdx = userinfo.indexOf(":");
        if (colonIdx !== -1) {
          uuid = userinfo.substring(colonIdx + 1);
        } else {
          uuid = userinfo;
        }

        let hp = hostPortRaw;
        const m = hp.match(/:(\d+)$/);
        if (m) {
          port = parseInt(m[1], 10) || 443;
          host = hp.substring(0, m.index);
        } else {
          host = hp || host;
        }
      } else {
        // 直接 host[:port]
        let hp = main;
        const m = hp.match(/:(\d+)$/);
        if (m) {
          port = parseInt(m[1], 10) || 443;
          host = hp.substring(0, m.index);
        } else {
          host = hp || host;
        }
      }
    }

    // ========== TLS / Reality / XTLS / WS 等参数 ==========
    const tlsParam =
      (params.get("tls") || "").toLowerCase() ||
      (params.get("security") || "").toLowerCase();
    const tls =
      tlsParam === "1" ||
      tlsParam === "true" ||
      tlsParam === "tls";

    // Reality
    const pbk = params.get("pbk") || params.get("public-key") || "";
    const sid = params.get("sid") || params.get("short-id") || "";

    // xtls-rprx-vision
    const xtls = params.get("xtls") || "";
    let flow = "";
    if (xtls === "2") {
      flow = "xtls-rprx-vision";
    }

    // obfs / websocket
    const obfs = (params.get("obfs") || "").toLowerCase();
    let network = "tcp";
    if (obfs === "websocket" || obfs === "ws") {
      network = "ws";
    }

    // path
    let path = "/";
    const pathParam = params.get("path");
    if (pathParam) {
      try {
        path = decodeURIComponent(pathParam) || "/";
      } catch (_e) {
        path = pathParam || "/";
      }
    }

    // Host / SNI / servername
    let hostHeader = "";
    const obfsParam = params.get("obfsParam") || params.get("host") || "";
    if (obfsParam) {
      try {
        hostHeader = decodeURIComponent(obfsParam);
      } catch (_e) {
        hostHeader = obfsParam;
      }
    }

    const peer = params.get("peer") || params.get("sni") || "";
    const servername = peer || host;

    // allowInsecure / insecure
    const insecure =
      (params.get("allowInsecure") || params.get("insecure") || "").toLowerCase();
    const skipCertVerify = insecure === "1" || insecure === "true";

    if (!name) {
      name = `${host}:${port}`;
    }

    return {
      raw: uri,
      type: "vless",
      server: host,
      port,
      uuid,
      tls,
      network,
      path,
      hostHeader,
      flow,
      servername,
      pbk,
      sid,
      skipCertVerify,
      name,
    };
  } catch (_e) {
    return null;
  }
}

/* ================= 工具函数 ================= */

function decodeNameMaybeTwice(str) {
  let s = str || "";
  try {
    if (s.includes("%")) s = decodeURIComponent(s);
  } catch (_e) {}
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
