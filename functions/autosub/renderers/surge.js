/*
 * 文件路径：functions/autosub/renderers/surge.js
 * 文件作用：
 *   - 将标准 Node[] 渲染为 Surge 可用的代理列表
 *   - 当前仅支持协议：ss / vmess / hysteria2 / trojan
 *   - 其它协议暂不转换（只在末尾做统计提示）
 */

/*
 * 生成安全的代理名称：
 *   - 优先用 node.name
 *   - 没有就用 协议前缀 + server:port
 *   - 去掉换行、逗号、等号等特殊字符
 */
function makeProxyName(node, fallbackPrefix) {
  const rawName = (node && node.name) || "";
  const base = (
    rawName ||
    `${fallbackPrefix}-${node.server || "unknown"}:${node.port || ""}`
  )
    .toString()
    .trim();

  return (
    base
      .replace(/[\r\n]/g, " ")
      .replace(/[=]/g, "-")
      .replace(/,/g, "、") || `${fallbackPrefix}-${Date.now()}`
  );
}

/*
 * 渲染 Shadowsocks 节点为 Surge 代理行
 * 参考格式：
 *   NAME = ss, server, port, encrypt-method=aes-128-gcm, password=xxxx, udp-relay=true, tfo=true
 */
function renderSS(node) {
  if (!node.server || !node.port || !node.cipher || !node.password) return null;

  const name = makeProxyName(node, "SS");
  const parts = [
    `${name} = ss`,
    node.server,
    node.port,
    `encrypt-method=${node.cipher}`,
    `password=${node.password}`,
    "udp-relay=true",
    "tfo=true",
  ];

  // plugin 暂时不展开，避免兼容性问题
  return parts.join(", ");
}

/*
 * 渲染 Trojan 节点为 Surge 代理行
 * 参考格式：
 *   NAME = trojan, server, port, password=xxx, sni=example.com, skip-cert-verify=true, udp-relay=true, tfo=true
 */
function renderTrojan(node) {
  if (!node.server || !node.port || !node.password) return null;

  const name = makeProxyName(node, "Trojan");
  const parts = [
    `${name} = trojan`,
    node.server,
    node.port,
    `password=${node.password}`,
    "udp-relay=true",
    "tfo=true",
  ];

  if (node.sni) {
    parts.push(`sni=${node.sni}`);
  }

  if (node.skipCertVerify === true) {
    parts.push("skip-cert-verify=true");
  }

  return parts.join(", ");
}

/*
 * 渲染 VMess 节点为 Surge 代理行
 * 参考格式（Surge 5+）：
 *   NAME = vmess, server, port, username=<uuid>, tls=true, sni=example.com,
 *          ws=true, ws-path=/xxx, ws-headers=Host:example.com
 */
function renderVmess(node) {
  if (!node.server || !node.port || !node.uuid) return null;

  const name = makeProxyName(node, "VMess");
  const parts = [
    `${name} = vmess`,
    node.server,
    node.port,
    `username=${node.uuid}`,
    "udp-relay=true",
    "tfo=true",
  ];

  // Surge 一般 encrypt-method=auto 即可
  parts.push("encrypt-method=auto");

  const security = String(node.security || "").toLowerCase();

  // TLS
  if (node.tls === true || security === "tls") {
    parts.push("tls=true");
    if (node.sni) {
      parts.push(`sni=${node.sni}`);
    }
  }

  const net = String(node.network || "").toLowerCase();

  // WebSocket
  if (net === "ws" || net === "websocket") {
    parts.push("ws=true");
    if (node.path) {
      parts.push(`ws-path=${node.path}`);
    }
    const host = node.host || node.sni;
    if (host) {
      parts.push(`ws-headers=Host:${host}`);
    }
  }

  // gRPC
  if (net === "grpc") {
    parts.push("grpc=true");
    const serviceName =
      node.path ||
      node.serviceName ||
      node["grpc-service-name"] ||
      "";
    if (serviceName) {
      parts.push(`grpc-service-name=${serviceName}`);
    }
  }

  return parts.join(", ");
}

/*
 * 渲染 Hysteria2 节点为 Surge 代理行
 * 参考格式：
 *   NAME = hysteria2, server, port, password=xxx, sni=example.com,
 *          skip-cert-verify=true, udp-relay=true, tfo=true
 */
function renderHy2(node) {
  const pwd = node.password || node.auth;
  if (!node.server || !node.port || !pwd) return null;

  const name = makeProxyName(node, "Hy2");
  const parts = [
    `${name} = hysteria2`,
    node.server,
    node.port,
    `password=${pwd}`,
    "udp-relay=true",
    "tfo=true",
  ];

  if (node.sni) {
    parts.push(`sni=${node.sni}`);
  }

  if (node.skipCertVerify === true) {
    parts.push("skip-cert-verify=true");
  }

  if (node.alpn) {
    parts.push(`alpn=${node.alpn}`);
  }
  if (node.obfs) {
    parts.push(`obfs=${node.obfs}`);
  }

  return parts.join(", ");
}

/*
 * 主渲染函数：Node[] → Surge 配置文本
 *
 * 支持：
 *   - ss
 *   - vmess
 *   - hysteria2 (包含标准化的 hysteria / hy2)
 *   - trojan
 *
 * 返回：
 *   - { body, contentType }
 */
export function renderSurge(nodes = []) {
  const lines = [];
  const unsupportedTypes = {};
  let supportedCount = 0;

  lines.push("# AUTOSUB · Surge Proxy List");
  lines.push("# 支持协议：ss / vmess / hysteria2 / trojan");
  lines.push("# 其它协议暂不转换，仅在末尾统计，方便排查");
  lines.push("");
  lines.push("[Proxy]");

  for (const n of nodes || []) {
    if (!n || !n.type) continue;
    const type = String(n.type || "").toLowerCase();

    let line = null;

    if (type === "ss") {
      line = renderSS(n);
    } else if (type === "trojan") {
      line = renderTrojan(n);
    } else if (type === "vmess") {
      line = renderVmess(n);
    } else if (type === "hysteria2" || type === "hysteria" || type === "hy2") {
      line = renderHy2(n);
    } else {
      unsupportedTypes[type] = (unsupportedTypes[type] || 0) + 1;
    }

    if (line) {
      lines.push(line);
      supportedCount++;
    }
  }

  if (supportedCount === 0) {
    lines.push("# （未找到可转换为 Surge 的支持协议节点）");
  }

  const uns = Object.entries(unsupportedTypes);
  if (uns.length) {
    lines.push("");
    lines.push("# ===== 未转换的协议统计（仅提示，不影响使用） =====");
    for (const [t, count] of uns) {
      lines.push(`# ${t}: ${count} 条`);
    }
  }

  const body = lines.join("\n");
  return {
    body,
    contentType: "text/plain; charset=utf-8",
  };
}
