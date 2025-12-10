/* renderers/clash.js
 * =================================================
 * 职责：
 *   - Node[] → Clash / Mihomo 简单完整配置
 *
 * 配置特点：
 *   - 基础端口：port / socks-port / allow-lan / mode / log-level
 *   - DNS：使用阿里传统 DNS（223.5.5.5, 223.6.6.6）
 *   - 主代理组名称：🐹 · Select
 *   - 规则：
 *       • 本机 / 局域网常用网段 → DIRECT（等价于 “LAN=直连”）
 *       • CN → DIRECT
 *       • 兜底 → 🐹 · Select
 */

function push(lines, text, indentLevel = 0) {
  const indent = "  ".repeat(indentLevel);
  lines.push(indent + text);
}

function escapeYamlString(str) {
  return String(str || "").replace(/"/g, '\\"');
}

/* Node → Clash proxy 对象 */
function nodeToClashProxy(node) {
  if (!node || !node.type) return null;

  const type = String(node.type).toLowerCase();
  const server =
    node.server ||
    node.add ||
    node.address ||
    node.host ||
    "";
  const port = Number(node.port || node.server_port || 0);
  if (!server || !port) return null;

  const name = node.name || `${server}:${port}`;

  /* Shadowsocks */
  if (type === "ss") {
    const cipher = node.cipher || node.method;
    const password = node.password;
    if (!cipher || !password) return null;

    const p = {
      _type: "ss",
      name,
      server,
      port,
      cipher,
      password,
    };

    if (node.plugin) {
      p.plugin = node.plugin;
    }
    if (node.pluginOpts) {
      p["plugin-opts"] = { mode: node.pluginOpts };
    }

    return p;
  }

  /* VMess */
  if (type === "vmess") {
    const uuid = node.uuid || node.id;
    if (!uuid) return null;

    const net =
      node.network ||
      node.net ||
      node.type ||
      "tcp";
    const tls = !!node.tls;
    const sni =
      node.sni ||
      node.host ||
      node.servername ||
      "";

    const p = {
      _type: "vmess",
      name,
      server,
      port,
      uuid,
      alterId: Number(node.alterId || node.aid || 0),
      cipher: node.security || node.encryption || "auto",
      tls,
    };

    if (sni) p.sni = sni;
    if (net && net !== "tcp") p.network = net;

    if (net === "ws") {
      const path = node.path || "/";
      const host =
        node.host ||
        node.wsHost ||
        sni ||
        "";
      p["ws-opts"] = {
        path,
        ...(host ? { headers: { Host: host } } : {}),
      };
    }

    if (net === "grpc") {
      const serviceName =
        node.path ||
        node.serviceName ||
        "";
      p["grpc-opts"] = {
        "grpc-service-name": serviceName,
      };
    }

    return p;
  }

  /* VLESS */
  if (type === "vless") {
    const uuid = node.uuid;
    if (!uuid) return null;

    const net =
      node.network ||
      node.net ||
      node.type ||
      "tcp";
    const tls = !!node.tls;
    const sni =
      node.sni ||
      node.host ||
      node.servername ||
      "";

    const p = {
      _type: "vless",
      name,
      server,
      port,
      uuid,
      flow: node.flow || "",
      tls,
    };

    if (sni) p.sni = sni;
    if (net && net !== "tcp") p.network = net;

    if (net === "ws") {
      const path = node.path || "/";
      const host =
        node.host ||
        node.wsHost ||
        sni ||
        "";
      p["ws-opts"] = {
        path,
        ...(host ? { headers: { Host: host } } : {}),
      };
    }

    if (net === "grpc") {
      const serviceName =
        node.path ||
        node.serviceName ||
        "";
      p["grpc-opts"] = {
        "grpc-service-name": serviceName,
      };
    }

    return p;
  }

  /* Trojan */
  if (type === "trojan") {
    const password = node.password;
    if (!password) return null;

    const net =
      node.network ||
      node.type ||
      "tcp";
    const sni =
      node.sni ||
      node.host ||
      "";

    const p = {
      _type: "trojan",
      name,
      server,
      port,
      password,
    };

    if (sni) p.sni = sni;
    if (net && net !== "tcp") p.network = net;

    if (net === "ws") {
      const path = node.path || "/";
      const host =
        node.host ||
        sni ||
        "";
      p["ws-opts"] = {
        path,
        ...(host ? { headers: { Host: host } } : {}),
      };
    }

    if (net === "grpc") {
      const serviceName =
        node.path ||
        node.serviceName ||
        "";
      p["grpc-opts"] = {
        "grpc-service-name": serviceName,
      };
    }

    return p;
  }

  /* Hysteria2 / hy2 / hysteria */
  if (type === "hysteria2" || type === "hy2" || type === "hysteria") {
    const password = node.password || node.auth;
    if (!password) return null;

    const p = {
      _type: "hysteria2",
      name,
      server,
      port,
      password,
      sni: node.sni || node.peer || "",
      up: node.upmbps || node.up || "",
      down: node.downmbps || node.down || "",
      alpn: node.alpn || "",
      "skip-cert-verify": !!node.skipCertVerify,
    };

    if (node.ports) {
      p.ports = node.ports;
    }
    if (node.obfs) {
      p.obfs = node.obfs;
      if (node.obfsPassword) {
        p["obfs-param"] = node.obfsPassword;
      }
    }

    return p;
  }

  return null;
}

/* 生成「简单完整 Clash 配置」的 YAML */
function buildFullConfigYaml(proxies, stats) {
  const lines = [];
  const MAIN_GROUP_NAME = "🐹 · Select"; /* “选择” 用英语 */

  lines.push("# Generated by autosub (Clash/Mihomo Simple Config)");
  lines.push(
    `# stats: total=${proxies.length}, ss=${stats.ss}, vmess=${stats.vmess}, vless=${stats.vless}, trojan=${stats.trojan}, hysteria2=${stats.hysteria2}`,
  );
  lines.push("");

  /* 基础配置 */
  lines.push("port: 7890");
  lines.push("socks-port: 7891");
  lines.push("allow-lan: true");
  lines.push("mode: Rule");
  lines.push("log-level: info");
  lines.push("");

  /* DNS：阿里传统 DNS */
  lines.push("dns:");
  push(lines, "enable: true", 1);
  push(lines, "listen: 0.0.0.0:53", 1);
  push(lines, "ipv6: false", 1);
  push(lines, "default-nameserver:", 1);
  push(lines, " - 223.5.5.5", 2);
  push(lines, " - 223.6.6.6", 2);
  push(lines, "nameserver:", 1);
  push(lines, " - 223.5.5.5", 2);
  push(lines, " - 223.6.6.6", 2);
  lines.push("");

  /* proxies 段 */
  lines.push("proxies:");
  if (proxies.length === 0) {
    push(lines, "# (no valid proxies parsed)", 1);
  } else {
    for (const p of proxies) {
      push(lines, `- name: "${escapeYamlString(p.name)}"`, 1);
      push(lines, `type: ${p._type}`, 2);
      push(lines, `server: ${p.server}`, 2);
      push(lines, `port: ${p.port}`, 2);

      if (p._type === "ss") {
        push(lines, `cipher: ${p.cipher}`, 2);
        push(
          lines,
          `password: "${escapeYamlString(p.password)}"`,
          2,
        );
        if (p.plugin) {
          push(lines, `plugin: ${p.plugin}`, 2);
        }
      } else if (p._type === "vmess") {
        push(lines, `uuid: ${p.uuid}`, 2);
        push(lines, `alterId: ${p.alterId || 0}`, 2);
        push(lines, `cipher: ${p.cipher || "auto"}`, 2);
        if (p.tls) push(lines, "tls: true", 2);
        if (p.sni) push(lines, `sni: ${p.sni}`, 2);
        if (p.network) push(lines, `network: ${p.network}`, 2);
        if (p["ws-opts"]) {
          push(lines, "ws-opts:", 2);
          push(lines, `path: "${p["ws-opts"].path || "/"}"`, 3);
          const headers = p["ws-opts"].headers || {};
          const host = headers.Host || headers.host;
          if (host) {
            push(lines, "headers:", 3);
            push(
              lines,
              `Host: "${escapeYamlString(host)}"`,
              4,
            );
          }
        }
        if (p["grpc-opts"]) {
          push(lines, "grpc-opts:", 2);
          if (p["grpc-opts"]["grpc-service-name"]) {
            push(
              lines,
              `grpc-service-name: "${escapeYamlString(
                p["grpc-opts"]["grpc-service-name"],
              )}"`,
              3,
            );
          }
        }
      } else if (p._type === "vless") {
        push(lines, `uuid: ${p.uuid}`, 2);
        if (p.flow) {
          push(lines, `flow: "${escapeYamlString(p.flow)}"`, 2);
        }
        if (p.tls) push(lines, "tls: true", 2);
        if (p.sni) push(lines, `sni: ${p.sni}`, 2);
        if (p.network) push(lines, `network: ${p.network}`, 2);
        if (p["ws-opts"]) {
          push(lines, "ws-opts:", 2);
          push(lines, `path: "${p["ws-opts"].path || "/"}"`, 3);
          const headers = p["ws-opts"].headers || {};
          const host = headers.Host || headers.host;
          if (host) {
            push(lines, "headers:", 3);
            push(
              lines,
              `Host: "${escapeYamlString(host)}"`,
              4,
            );
          }
        }
        if (p["grpc-opts"]) {
          push(lines, "grpc-opts:", 2);
          if (p["grpc-opts"]["grpc-service-name"]) {
            push(
              lines,
              `grpc-service-name: "${escapeYamlString(
                p["grpc-opts"]["grpc-service-name"],
              )}"`,
              3,
            );
          }
        }
      } else if (p._type === "trojan") {
        push(
          lines,
          `password: "${escapeYamlString(p.password)}"`,
          2,
        );
        if (p.sni) push(lines, `sni: ${p.sni}`, 2);
        if (p.network) push(lines, `network: ${p.network}`, 2);
        if (p["ws-opts"]) {
          push(lines, "ws-opts:", 2);
          push(lines, `path: "${p["ws-opts"].path || "/"}"`, 3);
          const headers = p["ws-opts"].headers || {};
          const host = headers.Host || headers.host;
          if (host) {
            push(lines, "headers:", 3);
            push(
              lines,
              `Host: "${escapeYamlString(host)}"`,
              4,
            );
          }
        }
        if (p["grpc-opts"]) {
          push(lines, "grpc-opts:", 2);
          if (p["grpc-opts"]["grpc-service-name"]) {
            push(
              lines,
              `grpc-service-name: "${escapeYamlString(
                p["grpc-opts"]["grpc-service-name"],
              )}"`,
              3,
            );
          }
        }
      } else if (p._type === "hysteria2") {
        push(
          lines,
          `password: "${escapeYamlString(p.password)}"`,
          2,
        );
        if (p.sni) push(lines, `sni: ${p.sni}`, 2);
        if (p.up) push(lines, `up: ${p.up}`, 2);
        if (p.down) push(lines, `down: ${p.down}`, 2);
        if (p.alpn) push(lines, `alpn: ${p.alpn}`, 2);
        if (p["skip-cert-verify"])
          push(lines, "skip-cert-verify: true", 2);
        if (p.ports) push(lines, `ports: "${p.ports}"`, 2);
        if (p.obfs) push(lines, `obfs: ${p.obfs}`, 2);
        if (p["obfs-param"])
          push(
            lines,
            `obfs-param: "${escapeYamlString(p["obfs-param"])}"`,
            2,
          );
      }

      lines.push("");
    }
  }

  /* 主代理组：🐹 · Select */
  lines.push("proxy-groups:");
  push(lines, `- name: "${escapeYamlString(MAIN_GROUP_NAME)}"`, 1);
  push(lines, "type: select", 2);
  push(lines, "proxies:", 2);
  push(lines, "  - DIRECT", 3);
  push(lines, "  - REJECT", 3);
  for (const p of proxies) {
    push(
      lines,
      `- "${escapeYamlString(p.name)}"`,
      3,
    );
  }
  lines.push("");

  /* 规则：
   *   - 本机 / 局域网常用网段直连（LAN 全直连效果）
   *   - 国内 IP 直连
   *   - 兜底走 🐹 · Select
   */
  lines.push("rules:");
  lines.push("  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve");
  lines.push("  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
  lines.push("  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve");
  lines.push("  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve");
  lines.push("  - IP-CIDR,224.0.0.0/4,DIRECT,no-resolve");
  lines.push("  - IP-CIDR,240.0.0.0/4,DIRECT,no-resolve");
  lines.push("  - GEOIP,CN,DIRECT");
  lines.push(`  - MATCH,${MAIN_GROUP_NAME}`);

  return lines.join("\n");
}

/* 对外渲染 */
export function renderClash(nodes = [], meta = {}) {
  const proxies = [];
  const stats = {
    ss: 0,
    vmess: 0,
    vless: 0,
    trojan: 0,
    hysteria2: 0,
    other: 0,
  };

  for (const n of nodes || []) {
    const p = nodeToClashProxy(n);
    if (!p) continue;
    proxies.push(p);

    const t = p._type;
    if (t === "ss") stats.ss++;
    else if (t === "vmess") stats.vmess++;
    else if (t === "vless") stats.vless++;
    else if (t === "trojan") stats.trojan++;
    else if (t === "hysteria2") stats.hysteria2++;
    else stats.other++;
  }

  const body = buildFullConfigYaml(proxies, stats);

  return {
    body,
    contentType: "text/yaml; charset=utf-8",
  };
}