// functions/api/sub/Clash.js
//
// 支持输入：
// - URL 格式
// - URL / Base64 混合格式
// - Base64 单条 / 多条（整条订阅）
//
// 支持协议输出（仅支持白名单列表）：
// - Clash / Stash：
//      - Shadowsocks / UDP
//
// 已支持的客户端：
// - Clash / Clash Meta / Stash（通过 /api/sub?client=clash 或 client=stash 使用）
//
// 说明：
// - 本文件只处理 Clash / Stash 订阅：POST /api/sub/Clash，body 为原始节点文本。
// - 解析 + 白名单过滤都在本文件完成，Converter 只负责转发。
// - 输出格式：
//      proxies:
//        - {"type":"ss","server":"...","port":xxxx,"cipher":"...","password":"...","name":"..."}

export async function onRequestPost(context) {
  const { request } = context;
  let text = (await request.text()) || "";
  text = text.trim();

  if (!text) {
    return new Response("proxies: []\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 1) 尝试当成 Base64 订阅整段解码
  const compact = text.replace(/\s+/g, "");
  const decoded = safeBase64Decode(compact);
  if (decoded && decoded.includes("ss://")) {
    text = decoded;
  }

  // 2) 从混合文本中提取 SS 节点
  const nodes = parseMixedSsNodes(text);

  if (!nodes.length) {
    return new Response("proxies: []\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 3) 白名单：只保留 Shadowsocks / UDP
  const lines = [];
  for (const n of nodes) {
    const shape = getClashShape(n);
    if (shape !== "ss-udp") continue;

    if (!n.cipher || !n.password) continue;
    if (!n.server || !n.port) continue;

    const entry = {
      type: "ss",
      server: n.server,
      port: n.port,
      cipher: n.cipher,
      password: n.password,
      name: n.name || `${n.server}:${n.port}`,
    };

    lines.push("  - " + JSON.stringify(entry));
  }

  if (!lines.length) {
    return new Response("proxies: []\n", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const out = "proxies:\n" + lines.join("\n") + "\n";

  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// =============== 白名单：仅 SS / UDP ===============

function getClashShape(node) {
  const t = (node.type || "").toLowerCase();
  if (t === "ss") {
    // 无 HTTP 混淆 → 纯 SS / UDP
    if (
      node.plugin === "obfs" &&
      (node.pluginMode || "").toLowerCase() === "http"
    ) {
      // ss/http/udp 不在 Clash 当前白名单中
      return "";
    }
    return "ss-udp";
  }
  return "";
}

// =============== 提取并解析 SS 节点 ===============

function parseMixedSsNodes(text) {
  const nodes = [];
  const seen = new Set();

  const re = /(ss:\/\/[^\s#]+(?:#[^\s]*)?)/gi;
  let m;
  while ((m = re.exec(text))) {
    const uri = m[0].trim();
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);

    const parsed = parseShadowsocks(uri);
    if (parsed && parsed.type === "ss") {
      nodes.push(parsed);
    }
  }

  return nodes;
}

// =================== Shadowsocks 解析 ===================
//
// 支持：
// - ss://BASE64(method:password@host:port)#name
// - ss://method:password@host:port#name
// - 带 plugin=obfs-local;obfs=http;obfs-host=xxx 的 HTTP 混淆（当前 Clash 白名单不下发）

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

    // 支持整段 Base64：
    // ss://BASE64(method:password@host:port)#name
    const decodedMain = safeBase64Decode(main);
    if (
      decodedMain &&
      decodedMain.includes("@") &&
      decodedMain.includes(":")
    ) {
      main = decodedMain;
    }

    // userinfo@host:port
    const atIndex = main.lastIndexOf("@");
    if (atIndex === -1) return null;

    let userinfo = main.slice(0, atIndex);
    const hostPortRaw = main.slice(atIndex + 1);
    const hostPortNoPath = hostPortRaw.split("/")[0];

    // userinfo → method:password（userinfo 本身可能是 Base64）
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

    // 插件参数（当前只用来判断是否 HTTP 混淆）
    let plugin = "";
    let pluginMode = "";
    let pluginHost = "";

    if (queryStr) {
      const sp = new URLSearchParams(queryStr);

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
