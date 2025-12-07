// functions/api/sub/Clash.js
//
// 仅支持白名单列表（Clash / Mihomo / Meta / FlyClash 使用）：
// - Shadowsocks / UDP
// - Shadowsocks / HTTP / UDP
//
// 入口：POST /api/sub/Clash
// body：原始节点文本（支持 URL、Base64、URL+Base64 混合）
//
// 行为：
// - 只解析真正以 ss:// 开头的行
// - VLESS / VMESS / TROJAN / HYSTERIA 等一律忽略，不下发给 Clash
// - 输出为标准 Clash / Mihomo proxies 段（YAML）

export async function onRequestPost(context) {
  const { request } = context;
  let text = (await request.text()) || "";

  // 如果整个 body 是 Base64 订阅，就先整体解一层
  const compact = text.replace(/\s+/g, "");
  const decodedWhole = safeBase64Decode(compact);
  if (decodedWhole && decodedWhole.includes("ss://")) {
    text = decodedWhole;
  }

  const nodes = parseSsWhitelist(text);

  if (!nodes.length) {
    return new Response("# no ss nodes", {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const lines = [];
  lines.push("proxies:");
  for (const n of nodes) {
    const obj = {
      type: "ss",
      server: n.server,
      port: n.port,
      cipher: n.cipher,
      password: n.password,
      name: n.name,
    };

    // http 混淆
    if ((n.plugin || "").toLowerCase() === "obfs" && n.pluginMode) {
      obj.plugin = "obfs";
      const opts = { mode: n.pluginMode }; // http / tls
      if (n.pluginHost) {
        opts.host = n.pluginHost;
      }
      obj["plugin-opts"] = opts;
    }

    lines.push("  - " + JSON.stringify(obj));
  }

  return new Response(lines.join("\n") + "\n", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ========== 只解析 SS，并做白名单过滤 ========== */

// 白名单：只保留 ss-udp / ss-http-udp
function parseSsWhitelist(text) {
  const nodes = [];
  const seen = new Set();

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;

    // 关键点：只处理「整行以 ss:// 开头」的行
    // vless://xxxxss://xxxx 这种行会被直接略过
    if (!line.toLowerCase().startsWith("ss://")) continue;

    // 一行里如果后面还有注释，只取第一个连续的 ss://... 片段
    const uri = line.split(/\s+/)[0];
    if (!uri || seen.has(uri)) continue;
    seen.add(uri);

    const node = parseShadowsocks(uri);
    if (!node) continue;

    // 白名单：只允许两种形态
    const shape = getSsShape(node);
    if (shape !== "ss-udp" && shape !== "ss-http-udp") continue;

    nodes.push(node);
  }

  return nodes;
}

// 判断 SS 形态（白名单用）
function getSsShape(n) {
  const plugin = (n.plugin || "").toLowerCase();
  const mode = (n.pluginMode || "").toLowerCase();

  if (plugin === "obfs" && mode === "http") {
    return "ss-http-udp";
  }
  return "ss-udp";
}

/* ========== Shadowsocks 解析：ss:// ========== */

function parseShadowsocks(uri) {
  try {
    if (!uri.toLowerCase().startsWith("ss://")) return null;

    let u = uri.replace(/^ss:\/\//i, "");

    // 备注（节点名）
    let name = "";
    const hashIndex = u.indexOf("#");
    if (hashIndex !== -1) {
      const remarkPart = u.substring(hashIndex + 1);
      try {
        name = decodeURIComponent(remarkPart);
      } catch (_e) {
        name = remarkPart;
      }
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

    // 有些写法 main 整段是 Base64：method:password@host:port
    let decodedMain = safeBase64Decode(main);
    if (decodedMain && decodedMain.includes("@") && decodedMain.includes(":")) {
      main = decodedMain;
    }

    // userinfo@host:port
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

      // obfs=tls / obfs=http
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

      // plugin=obfs-local;obfs=http;obfs-host=xxx
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

/* ========== Base64 工具（和前面保持一致即可） ========== */

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
