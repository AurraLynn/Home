/*
  - 输入：
      Node[] + client 名（如 clash / stash / ficlash / nekobox / flyclash）
  - 输出：
      针对不同 client 的 YAML:
        Clash / Meta: 块状 YAML
        FIClash / NekoBox / FlyClash: JSON 一行写法（最大兼容）
  - 自动丢弃不支持的参数:
        fast-open, udp, alpn, down, up, ports ...
*/

function yamlQuote(v) {
  if (v === undefined || v === null) return '""';
  const s = String(v);
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

/** 将 proxy 对象中不兼容字段剔除 */
function safeProxyForClient(proxy, client) {
  const badKeys = [
    "fast-open",
    "udp",
    "up",
    "down",
    "alpn",
    "ports",
    "plugin",
    "plugin-opts",
  ];

  if (["ficlash", "flyclash", "nekobox", "nekoray"].includes(client)) {
    const safe = {};
    for (const [k, v] of Object.entries(proxy)) {
      if (badKeys.includes(k)) continue;
      safe[k] = v;
    }
    return safe;
  }

  return proxy;
}

/** 单个 proxy 块状 YAML 输出 */
function dumpProxyYaml(p) {
  const lines = [];
  lines.push(`  - name: ${yamlQuote(p.name)}`);
  lines.push(`    type: ${p.type}`);
  lines.push(`    server: ${yamlQuote(p.server)}`);
  lines.push(`    port: ${Number(p.port)}`);

  if (p.type === "ss") {
    if (p.cipher) lines.push(`    cipher: ${yamlQuote(p.cipher)}`);
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
  } else if (p.type === "trojan") {
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
    lines.push(`    tls: true`);
    if (p.sni) lines.push(`    sni: ${yamlQuote(p.sni)}`);
  } else if (p.type === "hysteria2") {
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
    if (p.sni) lines.push(`    sni: ${yamlQuote(p.sni)}`);
    if (typeof p["skip-cert-verify"] !== "undefined")
      lines.push(`    skip-cert-verify: ${p["skip-cert-verify"] ? "true" : "false"}`);
  }

  return lines.join("\n");
}

export function renderClash(nodes = [], client = "clash") {
  const proxies = [];
  for (const n of nodes) {
    if (!n || !n.server || !n.port) continue;
    const type = n.type?.toLowerCase() || "unknown";

    if (!["ss", "trojan", "hysteria2", "hy2"].includes(type)) continue;

    const p = {
      name: n.name || `${n.server}:${n.port}`,
      type: type === "hy2" ? "hysteria2" : type,
      server: n.server,
      port: Number(n.port),
      password: n.password || n.auth || "",
      sni: n.sni,
      "skip-cert-verify": n.skipCertVerify ?? true,
      "tfo": true,
    };

    proxies.push(safeProxyForClient(p, client));
  }

  const names = proxies.map((p) => p.name);
  const lines = [];

  lines.push("port: 7890");
  lines.push("socks-port: 7891");
  lines.push("mode: Rule");
  lines.push("allow-lan: true");
  lines.push("log-level: info");
  lines.push("");
  lines.push("proxies:");

  if (proxies.length === 0) {
    lines.push("  # no supported proxies parsed yet");
  } else {
    for (const p of proxies) {
      if (["ficlash", "flyclash", "nekobox", "nekoray"].includes(client)) {
        // 输出 JSON 一行模式
        lines.push("  - " + JSON.stringify(p));
      } else {
        // 输出块状 YAML
        lines.push(dumpProxyYaml(p));
      }
    }
  }

  lines.push("");
  lines.push("proxy-groups:");
  lines.push('  - name: "🐹Lyn · Node"');
  lines.push("    type: select");
  lines.push("    proxies:");
  if (names.length === 0) {
    lines.push("      - DIRECT");
  } else {
    for (const n of names) lines.push(`      - ${yamlQuote(n)}`);
  }

  lines.push("");
  lines.push("rules:");
  lines.push("  - GEOIP,LAN,DIRECT");
  lines.push("  - GEOIP,CN,DIRECT");
  lines.push("  - MATCH,🐹Lyn · Node");

  return {
    body: lines.join("\n"),
    contentType: "text/yaml; charset=utf-8",
  };
}
