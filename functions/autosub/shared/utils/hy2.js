/*
  - 支持输入格式：
      hysteria2://auth@host:port?...#name
      hy2://auth@host:port?...#name
      hysteria2://host:port?auth=xxx&...#name

  - 输出字段示例：
      {
        type: "hysteria2",
        name,
        server,
        port,
        password,          // auth
        sni,
        skipCertVerify,
        obfs,
        obfsPassword,
        alpn,              // 原始字符串，Clash 渲染时再拆
        up,
        down,
        ports,
        raw
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
    if (u.username) {
      password = decodeURIComponent(u.username);
    } else {
      password =
        sp.get("auth") ||
        sp.get("password") ||
        sp.get("auth_str") ||
        "";
    }

    if (!server || !port || !password) {
      throw new Error("hy2 lack server/port/password");
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
