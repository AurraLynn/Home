/* renderers/clash.js
 * 文件作用：
 *   - 把节点数组渲染为可用的 Clash / Mihomo 配置
 */

function escapeName(name) {
  return String(name || "").replace(/"/g, '\\"');
}

/* 把单个节点转换成 Clash proxies 里的配置行 */
function buildProxyLine(node) {
  const name = node.name || `${node.type.toUpperCase()}_${node.server}`;

  if (node.type === "ss") {
    const cipher = node.cipher || node.method || "chacha20-ietf-poly1305";
    const pwd = node.password || node.pwd || "";
    return `  - {name: "${escapeName(
      name,
    )}", type: ss, server: ${node.server}, port: ${node.port}, cipher: "${cipher}", password: "${pwd}", udp: true}`;
  }

  if (node.type === "vmess") {
    const uuid = node.id || node.uuid || "";
    const alterId = node.alterId || 0;
    const security = node.security || "auto";
    const network = node.network || node.net || "tcp";
    const sni = node.sni || "";
    const host = node.host || "";
    const path = node.path || "/";
    return `  - {name: "${escapeName(
      name,
    )}", type: vmess, server: ${node.server}, port: ${node.port}, uuid: "${uuid}", alterId: ${alterId}, cipher: "${security}", network: "${network}", tls: ${
      sni ? "true" : "false"
    }, sni: "${sni}", udp: true, ws-opts: {path: "${path}", headers: {Host: "${host}"}}}`;
  }

  if (node.type === "vless") {
    const uuid = node.id || node.uuid || "";
    const network = node.network || "tcp";
    const sni = node.sni || "";
    const host = node.host || "";
    const path = node.path || "/";
    return `  - {name: "${escapeName(
      name,
    )}", type: vless, server: ${node.server}, port: ${node.port}, uuid: "${uuid}", flow: "${node.flow || ""}", network: "${network}", tls: ${
      sni ? "true" : "false"
    }, sni: "${sni}", udp: true, ws-opts: {path: "${path}", headers: {Host: "${host}"}}}`;
  }

  if (node.type === "trojan") {
    const pwd = node.password || node.pwd || "";
    const sni = node.sni || "";
    return `  - {name: "${escapeName(
      name,
    )}", type: trojan, server: ${node.server}, port: ${node.port}, password: "${pwd}", sni: "${sni}", udp: true, skip-cert-verify: true}`;
  }

  if (node.type === "hysteria2") {
    const auth = node.auth || "";
    const sni = node.sni || "";
    return `  - {name: "${escapeName(
      name,
    )}", type: hysteria2, server: ${node.server}, port: ${node.port}, auth: "${auth}", sni: "${sni}", skip-cert-verify: true, fast-open: true}`;
  }

  // 未知协议简单兜底当 ss
  return `  - {name: "${escapeName(
    name,
  )}", type: ss, server: ${node.server}, port: ${node.port}, cipher: "chacha20-ietf-poly1305", password: "password", udp: true}`;
}

/* Clash 渲染入口：生成完整 YAML */
export function renderClash(nodes = [], { rawText } = {}) {
  const proxyLines = nodes.map((n) => buildProxyLine(n)).join("\n");

  const proxyNames = nodes.map((n) => `"${escapeName(n.name || `${n.type.toUpperCase()}_${n.server}`)}"`);

  const yaml = [
    "port: 7890",
    "socks-port: 7891",
    "allow-lan: true",
    'mode: Rule',
    'log-level: info',
    "",
    "dns:",
    "  enable: true",
    "  ipv6: false",
    "  nameserver:",
    '    - 223.5.5.5',
    '    - 223.6.6.6',
    "",
    "proxies:",
    proxyLines || "  # no proxies",
    "",
    "proxy-groups:",
    '  - name: "🐹 · Select"',
    "    type: select",
    "    proxies:",
    proxyNames.length ? proxyNames.map((n) => `      - ${n}`).join("\n") : "      - DIRECT",
    "",
    '  - name: "🐹 · Auto"',
    "    type: url-test",
    "    url: http://www.gstatic.com/generate_204",
    "    interval: 300",
    "    tolerance: 50",
    "    proxies:",
    proxyNames.length ? proxyNames.map((n) => `      - ${n}`).join("\n") : "      - DIRECT",
    "",
    "rules:",
    "  - GEOIP,LAN,DIRECT",
    "  - GEOIP,CN,DIRECT",
    '  - MATCH,"🐹 · Select"',
    "",
    "# === raw input backup ===",
    ...String(rawText || "")
      .split("\n")
      .map((l) => `# ${l}`),
  ].join("\n");

  return {
    body: yaml,
    contentType: "text/yaml; charset=utf-8",
  };
}