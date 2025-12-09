/*
  - 支持输入格式（任意一种即可）：

      hysteria2://password@host:port?...#name
      hy2://password@host:port?...#name
      hysteria2://host:port?password=xxx&...#name
      hy2://host:port?auth=xxx&...#name

  - 解析输出字段（Node）示例：

      {
        type: "hysteria2",
        name,              // 备注
        server,            // IP / 域名
        port,              // 端口
        password,          // 认证密码 / token
        sni,               // TLS SNI / peer
        skipCertVerify,    // 跳过证书校验
        obfs,              // 混淆类型
        obfsPassword,      // 混淆密码
        alpn,              // "h3,h2" 形式的字符串
        up,                // 上行限速，如 "40 Mbps"
        down,              // 下行限速，如 "200 Mbps"
        ports,             // 端口范围，如 "35000-39000"
        raw                // 原始链接
      }
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

    // 1. 优先用 username（hysteria2://password@host:port 形式）
    if (u.username) {
      password = decodeURIComponent(u.username);
    }

    // 2. 其次从 query 里拿（兼容多种写法）
    if (!password) {
      password =
        sp.get("auth") ||
        sp.get("password") ||
        sp.get("passwd") ||
        sp.get("auth_str") ||
        sp.get("psk") ||
        "";
    }

    // 即使拿不到 password，也先生成节点，后续渲染器里会再兜底尝试 raw 解析
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

    const up = sp.get("up") || sp.get("upload") || "";
    const down = sp.get("down") || sp.get("download") || "";
    const ports = sp.get("ports") || "";

    return {
      type: "hysteria2",
      name,
      server,
      port,
      password,
      sni,
      skipCertVerify,
      obfs,
      obfsPassword,
      alpn,
      up,
      down,
      ports,
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
