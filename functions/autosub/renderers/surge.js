/*
 * 文件路径：functions/autosub/renderers/surge.js
 * 文件作用：
 *   - 将标准 Node[] 渲染为 Surge 可用的代理列表
 *   - 当前仅支持协议：ss / vmess / hysteria2 / trojan
 *   - 其它协议暂不转换（只在末尾统计提示）
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
 * 格式化 SS 密码：
 *   - 如果是 URL 编码（包含 %3D 等），先 decode 一次
 *   - 外面包一层双引号，内部 " 做转义
 */
function formatSSPassword(pwd) {
  if (pwd == null) return '""';
  let out = String(pwd);

  if (out.includes("%")) {
    try {
      out = decodeURIComponent(out);
    } catch {
      // 解码失败就用原始值
    }
  }

  out = out.replace(/"/g, '\\"');
  return `"${out}"`;
}

/*
 * 渲染 Shadowsocks 节点为 Surge 代理行
 * 参考格式：
 *   NAME=ss,server,port,encrypt-method=...,password="...",udp-relay=true,tfo=true
 */
function renderSS(node) {
  if (!node.server || !node.port || !node.cipher || !node.password) return null;

  const name = makeProxyName(node, "SS");
  const parts = [
    `${name}=ss`,
    node.server,
    node.port,
    `encrypt-method=${node.cipher}`,
    `password=${formatSSPassword(node.password)}`,
    "udp-relay=true",
    "tfo=true",
  ];

  return parts.join(",");
}

/*
 * 渲染 Trojan 节点为 Surge 代理行
 * 参考格式：
 *   NAME=trojan,server,port,password=xxx,sni=example.com,skip-cert-verify=true,udp-relay=true,tfo=true
 */
function renderTrojan(node) {
  if (!node.server || !node.port || !node.password) return null;

  const name = makeProxyName(node, "Trojan");
  const parts = [
    `${name}=trojan`,
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

  return parts.join(",");
}

/*
 * 渲染 VMess 节点为 Surge 代理行
 *
 * 目标格式（你给的“正确转换”）：
 *   广港隧道-香港 A 5x=vmess,d.ewfewfs.click,27506,
 *       username=UUID,
 *       ws=true,
 *       ws-path=/,
 *       ws-headers=Host:"tms.dingtalk.com",
 *       vmess-aead=true,
 *       tls=false
 */
function renderVmess(node) {
  if (!node.server || !node.port || !node.uuid) return null;

  const name = makeProxyName(node, "VMess");
  const parts = [
    `${name}=vmess`,
    node.server,
    node.port,
    `username=${node.uuid}`,
  ];

  const security = String(node.security || "").toLowerCase();
  const net = String(node.network || "").toLowerCase();

  // WebSocket
  if (net === "ws" || net === "websocket") {
    parts.push("ws=true");
    if (node.path) {
      parts.push(`ws-path=${node.path}`);
    }
    const host = node.host || node.sni;
    if (host) {
      const hEsc = String(host).replace(/"/g, '\\"');
      parts.push(`ws-headers=Host:"${hEsc}"`);
    }
  }

  // vmess-aead：alterId=0 或缺省时认为启用 AEAD
  let a = node.alterId;
  if (typeof a === "string") {
    const n = Number(a);
    if (!Number.isNaN(n)) a = n;
  }
  const useAead = a === 0 || a === undefined || a === null;
  if (useAead) {
    parts.push("vmess-aead=true");
  }

  // TLS 显式写出 true/false，和你例子保持一致
  const tlsOn = node.tls === true || security === "tls";
  parts.push(`tls=${tlsOn ? "true" : "false"}`);

  return parts.join(",");
}

/*
 * 渲染 Hysteria2 节点为 Surge 代理行
 * 参考格式：
 *   NAME=hysteria2,server,port,password=xxx,sni=example.com,skip-cert-verify=true,udp-relay=true,tfo=true
 */
function renderHy2(node) {
  const pwd = node.password || node.auth;
  if (!node.server || !node.port || !pwd) return null;

  const name = makeProxyName(node, "Hy2");
  const parts = [
    `${name}=hysteria2`,
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

  return parts.join(",");
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
