/*
  - 输入支持：
      hysteria2://password@host:port?...#name
      hy2://password@host:port?...#name
      hysteria2://host:port?password=xxx&...#name
      hy2://host:port?auth=xxx&...#name

  - 输出 Node 字段（本文件只负责“尽可能解析”，不用管具体 client 怎么用）：
      type: "hysteria2"
      name               备注（# 后面）
      server             IP / 域名
      port               端口
      password           认证密码 / token（同时也挂一份到 auth）
      sni                TLS SNI / peer
      skipCertVerify     是否跳过证书校验（insecure / allowInsecure / allow_insecure）

      obfs               混淆类型（none / salamander 等）
      obfsPassword       混淆密码

      alpn               原始 ALPN 字符串，如 "h3,h2"
      up                 上行限速（字符串，例如 "40 Mbps"）
      down               下行限速（字符串，例如 "200 Mbps"）
      ports              端口范围（例如 "35000-39000"）

      flag               可选，国旗/地区代号（如 CA）
      title              可选，完整标题（如 "🇨🇦 加拿大2"）
      ping               可选，延迟（毫秒）
      created            可选，创建时间（时间戳）
      updated            可选，更新时间（时间戳）
      tfo                可选，TCP Fast Open 标记
      udp                可选，UDP 支持标记
      proto              可选，额外协议参数
      protoParam         可选，协议参数字符串
      obfsParam          可选，额外混淆参数
      data               可选，原订阅来源地址
      user               可选，用户名/UUID 之类（如果有就挂上）

      raw                原始完整链接字符串
*/

export function parseHy2(url) {
  if (!url || typeof url !== "string") return null;

  const full = url.trim();
  const [beforeHash, hashPart = ""] = full.split("#");
  const name = decodeURIComponent(hashPart.trim());
  const body = beforeHash.replace(/^(hysteria2|hy2):\/\//i, "");

  try {
    const u = new URL("http://" + body);
    const sp = u.searchParams;

    const server = u.hostname;
    const port = parseInt(u.port || "0", 10) || 0;

    let password = "";
    let user = "";

    if (u.username) {
      user = decodeURIComponent(u.username);
      password = user;
    }

    if (!password) {
      password =
        sp.get("auth") ||
        sp.get("password") ||
        sp.get("passwd") ||
        sp.get("auth_str") ||
        sp.get("psk") ||
        "";
    }

    const insecureVal =
      (sp.get("insecure") ||
        sp.get("allowInsecure") ||
        sp.get("allow_insecure") ||
        "").toLowerCase();
    const skipCertVerify =
      insecureVal === "1" || insecureVal === "true" || insecureVal === "yes";

    const sni =
      sp.get("sni") || sp.get("server_name") || sp.get("peer") || "";

    const obfs =
      sp.get("obfs") || sp.get("obfs-name") || sp.get("obfs_mode") || "";
    const obfsPassword =
      sp.get("obfs-password") ||
      sp.get("obfs_pwd") ||
      sp.get("obfs-passwd") ||
      "";

    const alpn = sp.get("alpn") || "";

    const up =
      sp.get("up") ||
      sp.get("upload") ||
      sp.get("upmbps") ||
      sp.get("up_mbps") ||
      "";
    const down =
      sp.get("down") ||
      sp.get("download") ||
      sp.get("downmbps") ||
      sp.get("down_mbps") ||
      "";
    const ports = sp.get("ports") || "";

    const flag = sp.get("flag") || "";
    const title = sp.get("title") || name || "";
    const ping = sp.get("ping") || "";
    const created = sp.get("created") || "";
    const updated = sp.get("updated") || "";
    const tfo = sp.get("tfo") || "";
    const udp = sp.get("udp") || "";
    const proto = sp.get("proto") || "";
    const protoParam = sp.get("protoParam") || "";
    const obfsParam = sp.get("obfsParam") || "";
    const data = sp.get("data") || "";

    return {
      type: "hysteria2",
      name: title || name,
      server,
      port,
      password,
      auth: password, // 多挂一份，方便转换器直接用
      sni,
      skipCertVerify,

      obfs,
      obfsPassword,

      alpn,
      up,
      down,
      ports,

      flag,
      title: title || name,
      ping,
      created,
      updated,
      tfo,
      udp,
      proto,
      protoParam,
      obfsParam,
      data,
      user,

      raw: full,
    };
  } catch (_e) {
    return {
      type: "hysteria2",
      name,
      raw: full,
    };
  }
}
