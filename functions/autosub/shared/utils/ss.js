/*
  Shadowsocks 解析工具

  - 支持的输入格式（SIP002 常见写法）：

      1) 完整 base64：
         ss://BASE64(method:password@host:port)#name
         例如：
         ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTo0MzIxNzgzYkB1c2EuZXhhbXBsZS5jb206MTIzNA==#US-1

      2) 只 base64 用户信息：
         ss://BASE64(method:password)@host:port#name
         例如（你现在遇到的这种）：
         ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpsRTl1TDVmUjN5Ujk@cncgzbgp01.224837439.xyz:14151#TW - 台湾-2

      3) 纯明文：
         ss://method:password@host:port#name

      均可附带 plugin 参数，例如：
         ?plugin=obfs-local;obfs=http;obfs-host=4aaef245bd.iqiyi.com;obfs-uri=/

  - 输出 Node 字段：

      {
        type: "ss",
        name: string,
        server: string,
        port: number,
        cipher: string,
        password: string,
        plugin?: string,        // 如 "obfs-local"
        pluginOpts?: {          // 可选
          mode?: string,        // obfs=http
          host?: string,        // obfs-host=...
          uri?: string,         // obfs-uri=...
          raw?: string          // 原始 plugin 字符串
        },
        raw: string             // 原始 url
      }

  - 设计原则：
      解析失败只返回 null，不抛异常，避免整条订阅崩溃。
*/

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");
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

function parsePlugin(search) {
  if (!search) return null;

  // search 可能是 "plugin=obfs-local;obfs=http;obfs-host=...;obfs-uri=/"
  // 也可能带其它参数，我们只关心 plugin= 这部分
  const q = String(search).replace(/^\?+/, "");
  const match = q.match(/(?:^|&)plugin=([^&]+)/i);
  if (!match || !match[1]) return null;

  let pluginRaw = match[1];
  try {
    pluginRaw = decodeURIComponent(pluginRaw);
  } catch {
    // ignore
  }

  const parts = pluginRaw.split(";").filter(Boolean);
  if (!parts.length) return null;

  const plugin = parts[0]; // 第一个是插件名，如 obfs-local

  const opts = { raw: pluginRaw };
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i];
    const [k, v] = seg.split("=", 2);
    if (!k) continue;
    const key = k.trim();
    const value = (v || "").trim();

    if (key === "obfs") {
      // obfs=http
      opts.mode = value;
    } else if (key === "obfs-host") {
      opts.host = value;
    } else if (key === "obfs-uri") {
      opts.uri = value || "/";
    } else {
      // 其它参数直接挂上
      opts[key] = value;
    }
  }

  return { plugin, pluginOpts: opts };
}

export function parseSS(url) {
  if (!url || typeof url !== "string") return null;

  const raw = url.trim();
  if (!raw.toLowerCase().startsWith("ss://")) return null;

  try {
    // 去掉 ss:// 前缀
    let rest = raw.slice(5);

    // 先切 name（# 后面的部分）
    let name = "";
    const hashIndex = rest.indexOf("#");
    if (hashIndex >= 0) {
      const namePart = rest.slice(hashIndex + 1);
      rest = rest.slice(0, hashIndex);
      try {
        name = decodeURIComponent(namePart);
      } catch {
        name = namePart;
      }
    }

    // 再切查询参数（?plugin=...）
    let search = "";
    const qIndex = rest.indexOf("?");
    if (qIndex >= 0) {
      search = rest.slice(qIndex);       // 含 '?'
      rest = rest.slice(0, qIndex);      // 去掉 ? 后面
    }

    // 现在 rest 只剩下：
    // 1) BASE64(method:pass@host:port)
    // 2) BASE64(method:pass)@host:port
    // 3) method:pass@host:port

    let userInfo = "";
    let hostPort = "";

    if (rest.includes("@")) {
      const atIndex = rest.lastIndexOf("@");
      userInfo = rest.slice(0, atIndex);
      hostPort = rest.slice(atIndex + 1);
    } else {
      // 没有 @，当成 base64(method:pass@host:port)
      const decoded = b64DecodeUrlSafe(rest);
      if (!decoded || !decoded.includes("@")) return null;
      const atIndex2 = decoded.lastIndexOf("@");
      userInfo = decoded.slice(0, atIndex2);
      hostPort = decoded.slice(atIndex2 + 1);
    }

    // 解析 host:port
    const hpParts = hostPort.split(":");
    if (hpParts.length < 2) return null;
    const server = hpParts[0].trim();
    const port = Number(hpParts[1].trim());
    if (!server || !Number.isFinite(port)) return null;

    // 解析 userInfo：
    // 可能是：
    //   method:password           （明文）
    //   BASE64(method:password)   （无冒号，整体是 base64）
    let method = "";
    let password = "";

    if (userInfo.includes(":")) {
      // 明文 method:password
      const idx = userInfo.indexOf(":");
      method = userInfo.slice(0, idx);
      password = userInfo.slice(idx + 1);
    } else {
      // base64(method:password)
      const decodedUser = b64DecodeUrlSafe(userInfo);
      if (!decodedUser || !decodedUser.includes(":")) return null;
      const idx2 = decodedUser.indexOf(":");
      method = decodedUser.slice(0, idx2);
      password = decodedUser.slice(idx2 + 1);
    }

    method = method.trim();
    password = password.trim();
    if (!method || !password) return null;

    // 解析 plugin
    let plugin;
    let pluginOpts;
    if (search) {
      const pluginParsed = parsePlugin(search);
      if (pluginParsed) {
        plugin = pluginParsed.plugin;
        pluginOpts = pluginParsed.pluginOpts;
      }
    }

    return {
      type: "ss",
      name: name || `${server}:${port}`,
      server,
      port,
      cipher: method,
      password,
      ...(plugin ? { plugin } : {}),
      ...(pluginOpts ? { pluginOpts } : {}),
      raw,
    };
  } catch (_e) {
    // 任何异常直接返回 null，不让整个订阅崩掉
    return null;
  }
}
