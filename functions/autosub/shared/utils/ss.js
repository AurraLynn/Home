/**
 * SS 解析器（尽量完整）
 *
 * 支持形态：
 * 1) ss://BASE64(method:password)@host:port?plugin=...#name
 * 2) ss://BASE64(method:password@host:port)?plugin=...#name
 * 3) ss://method:password@host:port?plugin=...#name
 *
 * 输出字段：
 * { type, server, port, cipher, password, name, plugin, pluginOpts, raw }
 */

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  try {
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

/**
 * 解析 plugin 参数
 * 形如：
 *  obfs-local;obfs=http;obfs-host=example.com;obfs-uri=/
 *  v2ray-plugin;mode=websocket;host=xx;path=/;tls=true
 */
function parsePluginParam(pluginParam) {
  if (!pluginParam) return { plugin: "", pluginOpts: null };

  const raw = safeDecode(pluginParam);
  const segs = raw.split(";").filter(Boolean);
  const main = segs[0] || "";

  const kv = {};
  for (const seg of segs.slice(1)) {
    const [k, v] = seg.split("=");
    if (k) kv[k] = v ?? "";
  }

  // 映射到 Clash 常见写法
  if (main.includes("obfs")) {
    return {
      plugin: "obfs",
      pluginOpts: {
        mode: kv["obfs"] || kv["mode"] || "http",
        host: kv["obfs-host"] || kv["host"] || "",
        path: kv["obfs-uri"] || kv["path"] || "",
      },
    };
  }

  if (main.includes("v2ray-plugin")) {
    const tlsVal = (kv["tls"] || "").toLowerCase();
    const tls =
      tlsVal === "1" || tlsVal === "true" || tlsVal === "tls";

    return {
      plugin: "v2ray-plugin",
      pluginOpts: {
        mode: kv["mode"] || "websocket",
        host: kv["host"] || "",
        path: kv["path"] || "",
        tls,
      },
    };
  }

  // 其它未知 plugin：保留原始参数（不丢）
  return {
    plugin: main || "plugin",
    pluginOpts: Object.keys(kv).length ? kv : null,
  };
}

/**
 * 解析 ss:// 原始链接
 */
export function parseSS(raw) {
  const s = String(raw || "").trim();
  if (!s.startsWith("ss://")) return null;

  // 尝试 URL 解析（对 1/3 形态很友好）
  try {
    const u = new URL(s);

    const name = safeDecode((u.hash || "").replace(/^#/, "")) || "";

    const server = u.hostname || "";
    const port = Number(u.port || 0);

    // plugin
    const pluginParam = u.searchParams.get("plugin") || "";
    const { plugin, pluginOpts } = parsePluginParam(pluginParam);

    // 形态 3：ss://method:password@host:port
    if (u.username && u.password) {
      const cipher = safeDecode(u.username);
      const password = safeDecode(u.password);

      if (!server || !port || !cipher || !password) return null;

      return {
        type: "ss",
        server,
        port,
        cipher,
        password,
        name: name || `${server}:${port}`,
        plugin,
        pluginOpts,
        raw: s,
      };
    }

    // 形态 1：ss://BASE64(method:password)@host:port
    if (u.username && !u.password) {
      const decoded = b64DecodeUrlSafe(u.username);
      const [cipher, password] = decoded.split(":");

      if (!server || !port || !cipher || !password) {
        // 继续走 fallback
      } else {
        return {
          type: "ss",
          server,
          port,
          cipher,
          password,
          name: name || `${server}:${port}`,
          plugin,
          pluginOpts,
          raw: s,
        };
      }
    }
  } catch {
    // URL 解析失败就走 fallback
  }

  // ===== fallback：处理形态 2（整段 base64） =====
  let rest = s.slice(5);

  // 提取 name
  let name = "";
  const hashIndex = rest.indexOf("#");
  if (hashIndex >= 0) {
    name = safeDecode(rest.slice(hashIndex + 1));
    rest = rest.slice(0, hashIndex);
  }

  // 提取 query（拿 plugin）
  let query = "";
  const qIndex = rest.indexOf("?");
  if (qIndex >= 0) {
    query = rest.slice(qIndex + 1);
    rest = rest.slice(0, qIndex);
  }

  const pluginParam = (() => {
    if (!query) return "";
    const sp = new URLSearchParams(query);
    return sp.get("plugin") || "";
  })();

  const { plugin, pluginOpts } = parsePluginParam(pluginParam);

  const decoded = b64DecodeUrlSafe(rest);
  if (!decoded || !decoded.includes("@")) return null;

  const [left, right] = decoded.split("@");
  const [cipher, password] = left.split(":");
  const [server, portStr] = right.split(":");
  const port = Number(portStr);

  if (!server || !port || !cipher || !password) return null;

  return {
    type: "ss",
    server,
    port,
    cipher,
    password,
    name: name || `${server}:${port}`,
    plugin,
    pluginOpts,
    raw: s,
  };
}
