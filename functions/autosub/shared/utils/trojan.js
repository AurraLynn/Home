// functions/api/sub/shared/utils/trojan.js

// 解析 trojan:// 链接（URL 型）
// 例如：
// trojan://password@host:port?allowInsecure=1&sni=example.com&type=ws&host=xxx&path=/ws#备注
export function parseTrojan(url) {
  if (!url || typeof url !== "string") return null;

  const full = url.trim();

  // 备注在 # 后面（URL 编码）
  const remarkPart = full.split("#")[1] || "";
  const name = decodeURIComponent(remarkPart.trim());

  // 去掉 trojan:// 前缀
  const body = full.replace(/^trojan:\/\//i, "");

  try {
    // 为了用 URL API，前面补一个假协议
    const u = new URL("http://" + body);
    const sp = u.searchParams;

    // allowInsecure / allow_insecure 控制是否跳过证书校验
    const allowInsecureVal =
      (sp.get("allowInsecure") || sp.get("allow_insecure") || "").toLowerCase();
    const skipCertVerify =
      allowInsecureVal === "1" || allowInsecureVal === "true";

    // 是否 WS
    const networkParam = (sp.get("type") || sp.get("network") || "tcp").toLowerCase();
    const isWs = networkParam === "ws" || networkParam === "websocket";

    const node = {
      type: "trojan",
      name,
      server: u.hostname,
      port: Number(u.port || 443),
      password: decodeURIComponent(u.username || ""),
      tls: true, // trojan 默认走 TLS
      sni: sp.get("sni") || sp.get("peer") || "",
      skipCertVerify,
      network: isWs ? "ws" : "tcp",
      host: sp.get("host") || "",
      path: sp.get("path") || "",
      // 保留原串方便 debug
      raw: full,
    };

    return node;
  } catch (e) {
    // 解析失败就退回一个最小结构，避免整条丢掉
    return {
      type: "trojan",
      name,
      raw: full,
    };
  }
}
