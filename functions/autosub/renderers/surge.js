/*
 * 文件路径：functions/autosub/renderers/surge.js
 * 文件作用：
 *   - 将标准 Node[] 渲染为 Surge 可用的代理列表
 *   - 当前支持协议：ss / vmess / hysteria2 / trojan / anytls / tuic
 *   - 其它协议暂不转换（只在末尾统计提示）
 */

/*
 * 生成安全的代理名称
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
 * 格式化 SS 密码
 */
function formatSSPassword(pwd) {
  if (pwd == null) return '""';
  let out = String(pwd);

  if (out.includes("%")) {
    try {
      out = decodeURIComponent(out);
    } catch {}
  }

  out = out.replace(/"/g, '\\"');
  return `"${out}"`;
}

/*
 * Shadowsocks
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
 * Trojan（重点修复）
 *
 * 修复点：
 *   - allowInsecure → skip-cert-verify（多写法兼容）
 *   - SNI 自动补齐
 *   - 参数顺序优化
 */
function renderTrojan(node) {
  if (!node.server || !node.port || !node.password) return null;

  const name = makeProxyName(node, "Trojan");

  const parts = [
    `${name}=trojan`,
    node.server,
    node.port,
    `password=${node.password}`,
  ];

  // SNI（优先 node.sni，否则 fallback server）
  const sni = node.sni || node.server;
  if (sni) {
    parts.push(`sni=${sni}`);
  }

  // 🔥 核心修复：兼容所有来源字段
  const skip =
    node.skipCertVerify === true ||
    node["skip-cert-verify"] === true ||
    String(node.allowInsecure) === "1";

  if (skip) {
    parts.push("skip-cert-verify=true");
  }

  // UDP（默认开启）
  if (node.udp !== false) {
    parts.push("udp-relay=true");
  }

  // TFO
  if (node.tfo === true) {
    parts.push("tfo=true");
  }

  return parts.join(",");
}

/*
 * VMess
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

  if (net === "ws" || net === "websocket") {
    parts.push("ws=true");

    if (node.path) {
      parts.push(`ws-path=${node.path}`);
    }

    const host = node.host || node.sni || node.server;
    if (host) {
      const hEsc = String(host).replace(/"/g, '\\"');
      parts.push(`ws-headers=Host:"${hEsc}"`);
    }
  }

  let a = node.alterId;
  if (typeof a === "string") {
    const n = Number(a);
    if (!Number.isNaN(n)) a = n;
  }

  const useAead = a === 0 || a === undefined || a === null;
  if (useAead) {
    parts.push("vmess-aead=true");
  }

  const tlsOn = node.tls === true || security === "tls";
  parts.push(`tls=${tlsOn ? "true" : "false"}`);

  return parts.join(",");
}

/*
 * Hysteria2
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
  ];

  const sni = node.sni || node.server;
  if (sni) {
    parts.push(`sni=${sni}`);
  }

  if (
    node.skipCertVerify === true ||
    node["skip-cert-verify"] === true
  ) {
    parts.push("skip-cert-verify=true");
  }

  if (node.udp !== false) {
    parts.push("udp-relay=true");
  }

  if (node.tfo === true) {
    parts.push("tfo=true");
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
 * AnyTLS
 * Surge 官方格式：
 *   name = anytls, server, port, password=pwd, sni=example.com, skip-cert-verify=true, reuse=true
 */
function renderAnyTLS(node) {
  const pwd = node.password || node.auth;
  if (!node.server || !node.port || !pwd) return null;

  const name = makeProxyName(node, "AnyTLS");

  const parts = [
    `${name}=anytls`,
    node.server,
    node.port,
    `password=${pwd}`,
  ];

  const sni = node.sni || node.peer || node.serverName || node.servername || node.server;
  if (sni) {
    parts.push(`sni=${sni}`);
  }

  const skip =
    node.skipCertVerify === true ||
    node["skip-cert-verify"] === true ||
    String(node.allowInsecure) === "1" ||
    String(node.insecure) === "1";

  if (skip) {
    parts.push("skip-cert-verify=true");
  }

  // AnyTLS v2：Surge 默认启用连接复用；如果节点显式传了 reuse=false，就保留。
  if (node.reuse === false || String(node.reuse).toLowerCase() === "false") {
    parts.push("reuse=false");
  } else if (node.reuse === true || String(node.reuse).toLowerCase() === "true") {
    parts.push("reuse=true");
  }

  return parts.join(",");
}


/*
 * TUIC
 * Surge 常见格式：
 *   name=tuic,server,port,uuid=xxx,password=xxx,sni=example.com,alpn=h3,congestion-control=bbr,udp-relay-mode=native
 */
function renderTuic(node) {
  if (!node.server || !node.port) return null;

  const uuid = node.uuid || node.id || "";
  const password = node.password || node.pwd || "";
  const token = node.token || "";

  if (!token && (!uuid || !password)) return null;

  const name = makeProxyName(node, "TUIC");

  const parts = [
    `${name}=tuic`,
    node.server,
    node.port,
  ];

  if (uuid) {
    parts.push(`uuid=${uuid}`);
  }

  if (password) {
    parts.push(`password=${password}`);
  } else if (token) {
    // 兼容只有 token 的来源，避免直接丢节点
    parts.push(`password=${token}`);
  }

  const sni = node.sni || node.servername || node.serverName || node.server;
  if (sni) {
    parts.push(`sni=${sni}`);
  }

  const alpn = Array.isArray(node.alpn) ? node.alpn.join(",") : node.alpn;
  if (alpn) {
    parts.push(`alpn=${alpn}`);
  }

  const cc = String(
    node.congestionController ||
      node["congestion-controller"] ||
      node["congestion-control"] ||
      node.congestion_control ||
      ""
  )
    .trim()
    .replace(/_/g, "-");

  if (cc) {
    parts.push(`congestion-control=${cc}`);
  }

  const udpRelayMode = String(
    node.udpRelayMode ||
      node["udp-relay-mode"] ||
      node.udp_relay_mode ||
      ""
  )
    .trim()
    .replace(/_/g, "-");

  if (udpRelayMode) {
    parts.push(`udp-relay-mode=${udpRelayMode}`);
  }

  if (
    node.skipCertVerify === true ||
    node["skip-cert-verify"] === true ||
    String(node.allowInsecure) === "1" ||
    String(node.insecure) === "1"
  ) {
    parts.push("skip-cert-verify=true");
  }

  if (node.tfo === true) {
    parts.push("tfo=true");
  }

  if (node.reduceRtt === true || node["reduce-rtt"] === true) {
    parts.push("reduce-rtt=true");
  }

  if (node.udp !== false) {
    parts.push("udp-relay=true");
  }

  return parts.join(",");
}

/*
 * 主渲染函数
 */
export function renderSurge(nodes = []) {
  const lines = [];
  const unsupportedTypes = {};
  let supportedCount = 0;

  lines.push("# AUTOSUB · Surge Proxy List");
  lines.push("# 支持协议：ss / vmess / hysteria2 / trojan / anytls / tuic");
  lines.push("# 其它协议暂不转换，仅在末尾统计");
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
    } else if (type === "anytls") {
      line = renderAnyTLS(n);
    } else if (type === "tuic") {
      line = renderTuic(n);
    } else {
      unsupportedTypes[type] = (unsupportedTypes[type] || 0) + 1;
    }

    if (line) {
      lines.push(line);
      supportedCount++;
    }
  }

  if (supportedCount === 0) {
    lines.push("# （未找到可用节点）");
  }

  const uns = Object.entries(unsupportedTypes);
  if (uns.length) {
    lines.push("");
    lines.push("# ===== 未转换协议统计 =====");
    for (const [t, count] of uns) {
      lines.push(`# ${t}: ${count}`);
    }
  }

  return {
    body: lines.join("\n"),
    contentType: "text/plain; charset=utf-8",
  };
}
