/*
 * 文件路径：functions/autosub/shared/utils/ss.js
 * 文件作用：
 *   - 解析 Shadowsocks (ss://) 节点为标准 Node 对象
 *   - 支持：
 *       • 明文：ss://cipher:password@server:port#name
 *       • 整串 base64：ss://BASE64(cipher:password@server:port)#name
 *       • 2022-blake3 系列：cipher:password1:password2@server:port
 *   - 解析出字段：server / port / cipher / password / name / plugin / pluginOpts
 */

function safeDecodeURIComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

/*
 * 粗略判断一段文本是否像 base64
 */
function isLikelyBase64(s) {
  if (!s) return false;
  const t = String(s).trim();
  if (t.length < 8) return false;
  if (!/^[A-Za-z0-9+/_=-]+$/.test(t)) return false;
  return true;
}

/*
 * url-safe base64 解码（兼容 -/_）
 */
function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  try {
    return atob(s);
  } catch {
    return "";
  }
}

/*
 * 工具：拆分 server:port（使用最后一个 :，兼容 IPv6）
 */
function splitHostPort(str) {
  const s = (str || "").trim();
  if (!s) return ["", 0];

  const lastColon = s.lastIndexOf(":");
  if (lastColon < 0) {
    return [s, 0];
  }

  const host = s.slice(0, lastColon).trim();
  const portStr = s.slice(lastColon + 1).trim();
  const portNum = portStr ? Number(portStr) || 0 : 0;

  return [host, portNum];
}

/*
 * 主函数：解析 ss:// 节点
 */
export function parseSS(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw.toLowerCase().startsWith("ss://")) return null;

  // 1. 拆掉 #name（备注）
  let nameFromHash = "";
  let main = raw;
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    const hashPart = raw.slice(hashIndex + 1);
    nameFromHash = safeDecodeURIComponent(hashPart);
    main = raw.slice(0, hashIndex);
  }

  // 2. 去掉 ss://
  main = main.replace(/^ss:\/\//i, "");

  // 3. 拆 query（plugin 等）
  let mainPart = main;
  let query = "";
  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    mainPart = main.slice(0, qIndex);
    query = main.slice(qIndex + 1);
  }

  // 4. 解析 query 参数（主要是 plugin）
  const params = {};
  if (query) {
    const segs = query.split("&");
    for (const seg of segs) {
      if (!seg) continue;
      const [kRaw, vRaw = ""] = seg.split("=", 2);
      const k = (kRaw || "").trim();
      if (!k) continue;
      const key = safeDecodeURIComponent(k);
      const val = safeDecodeURIComponent(vRaw);
      params[key] = val;
    }
  }

  // 5. 处理 mainPart：
  //    情况 A：已经是 cipher:pwd@host:port
  //    情况 B：整串 base64("cipher:pwd@host:port")
  let work = mainPart.trim();

  let atIndex = work.indexOf("@");
  if (atIndex < 0 && isLikelyBase64(work)) {
    const decoded = b64DecodeUrlSafe(work);
    if (decoded && decoded.includes("@")) {
      work = decoded.trim();
      atIndex = work.indexOf("@");
    }
  }

  let userinfo = work;
  let hostPortPart = "";

  if (atIndex >= 0) {
    userinfo = work.slice(0, atIndex);
    hostPortPart = work.slice(atIndex + 1);
  }

  // 6. userinfo → cipher + password
  //    支持 2022-blake3 这种多冒号写法：
  //    cipher:pwd1:pwd2 → cipher = 第一段，其余全部合起来当 password
  let cipher = "";
  let password = "";

  if (userinfo) {
    const parts = userinfo.split(":");
    if (parts.length >= 2) {
      cipher = parts[0].trim();
      password = parts.slice(1).join(":").trim();
    }
  }

  // 7. host:port
  let server = "";
  let port = 0;
  if (hostPortPart) {
    const [h, p] = splitHostPort(hostPortPart);
    server = h;
    port = p;
  }

  // 8. plugin / plugin-opts
  const plugin = params.plugin || params["plugin-type"] || "";
  // 有些写法用 plugin-opts / plugin_opts
  const pluginOpts =
    params["plugin-opts"] || params["plugin_opts"] || params["pluginOpts"] || "";

  // 9. 返回 Node（即便不完整也返回，方便后续调试）
  return {
    type: "ss",
    raw,
    name: nameFromHash || (server && port ? `${server}:${port}` : raw),

    server: server,
    port: port,
    cipher: cipher,
    password: password,

    plugin: plugin || undefined,
    pluginOpts: pluginOpts || undefined,
  };
}
