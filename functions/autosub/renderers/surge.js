/* renderers/surge.js
 * 文件作用：
 *   - 把节点数组渲染为 Surge 使用的节点行
 */

function escapeName(name) {
  return String(name || "").replace(/,/g, "，");
}

/* 把单个节点转换成 Surge 里的配置行 */
function buildProxyLine(node) {
  const name = escapeName(
    node.name || `${node.type.toUpperCase()}_${node.server}`,
  );

  if (node.type === "ss") {
    const cipher = node.cipher || node.method || "aes-128-gcm";
    const pwd = node.password || node.pwd || "";
    return `${name} = shadowsocks, ${node.server}, ${node.port}, encrypt-method=${cipher}, password=${pwd}, udp-relay=true`;
  }

  if (node.type === "vmess") {
    const uuid = node.id || node.uuid || "";
    const tls = node.sni ? "tls=true" : "tls=false";
    const host = node.host || "";
    const path = node.path || "/";
    return `${name} = vmess, ${node.server}, ${node.port}, username=${uuid}, ${tls}, ws=true, ws-path="${path}", ws-headers=Host:${host}`;
  }

  if (node.type === "vless") {
    const uuid = node.id || node.uuid || "";
    const tls = node.sni ? "tls=true" : "tls=false";
    const host = node.host || "";
    const path = node.path || "/";
    return `${name} = vless, ${node.server}, ${node.port}, username=${uuid}, ${tls}, ws=true, ws-path="${path}", ws-headers=Host:${host}`;
  }

  if (node.type === "trojan") {
    const pwd = node.password || node.pwd || "";
    const sni = node.sni || "";
    return `${name} = trojan, ${node.server}, ${node.port}, password=${pwd}, sni=${sni}, skip-cert-verify=true`;
  }

  if (node.type === "hysteria2") {
    const auth = node.auth || "";
    const sni = node.sni || "";
    return `${name} = hysteria2, ${node.server}, ${node.port}, auth=${auth}, sni=${sni}, skip-cert-verify=true`;
  }

  // 未识别协议，兜底 direct，方便你一眼看出来有异常
  return `${name} = direct`;
}

/* Surge 渲染入口：只返回节点行，每行可直接放进 [Proxy] 段里 */
export function renderSurge(nodes = [], { rawText } = {}) {
  const lines = nodes.map((n) => buildProxyLine(n)).join("\n");

  const body = [
    lines || "# no proxies",
    "",
    "# === raw input backup ===",
    ...String(rawText || "")
      .split("\n")
      .map((l) => `# ${l}`),
  ].join("\n");

  return {
    body,
    contentType: "text/plain; charset=utf-8",
  };
}
