/* renderers/clash.js
 * =================================================
 * 职责：
 *   - Node[] → Clash / Mihomo / Stash 可用订阅内容
 *
 * 规则：
 *   1) 默认行为（浏览器、Clash、Mihomo 等）：
 *      - 输出一个「简单完整配置」：
 *          - port / socks-port / allow-lan / mode / log-level
 *          - proxies:
 *          - proxy-groups:
 *          - rules:
 *
 *   2) 针对 Stash（UA 包含 "stash"）：
 *      - 只输出 proxies: 段，不包含端口/规则/分组等全局配置
 *      - 因为 Stash 的订阅通常只接收节点列表，由本地配置接管其余部分
 *
 * ⚠️ 注意：
 *   - Stash 不需要完整配置，否则可能无法正确识别为「节点订阅」。
 *   - 逻辑：在 renderClash 中读取 meta.ua 根据 UA 判断。
 *   - Router.js 在调用 renderClash 时会传入 { ua }。
 */

/* 工具：追加一行 YAML 文本 */
function push(lines, text, indentLevel = 0) {
  const indent = "  ".repeat(indentLevel);
  lines.push(indent + text);
}

/* 工具：将字符串转成 YAML 安全形式（简单双引号转义） */
function escapeYamlString(str) {
  return String(str || "").replace(/"/g, '\\"');
}

/* Node → Clash 内部 proxy 对象（_type 区分协议） */
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

/* 构建「仅 proxies 段」的 YAML（给 Stash 用） */
function buildProxiesOnlyYaml(proxies, stats) {
  const lines = [];

  lines.push("# Generated by autosub (Clash/Stash Proxies Only)");
  lines.push(
    `# stats: total=${proxies.length}, ss=${stats.ss}, vmess=${stats.vmess}, vless=${stats.vless}, trojan=${stats.trojan}, hysteria2=${stats.hysteria2}`,
  );
  lines.push("");
  lines.push("proxies:");

  if (proxies.length === 0) {
    push(lines, "# (no valid proxies parsed)", 1);
    return lines.join("\n");
  }

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

  return lines.join("\n");
}

/* 构建「简单完整 Clash 配置」的 YAML（给 Clash/Mihomo 调试用） */
function buildFullConfigYaml(proxies, stats) {
  const lines = [];

  lines.push("# Generated by autosub (Clash/Mihomo Simple Config)");
  lines.push(
    `# stats: total=${proxies.length}, ss=${stats.ss}, vmess=${stats.vmess}, vless=${stats.vless}, trojan=${stats.trojan}, hysteria2=${stats.hysteria2}`,
  );
  lines.push("");

  // 基础配置（可按需要微调）
  lines.push("port: 7890");
  lines.push("socks-port: 7891");
  lines.push("allow-lan: true");
  lines.push("mode: Rule");
  lines.push("log-level: info");
  lines.push("");

  // proxies 段
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

  // 一个简单的 proxy-group，全部节点丢进去
  lines.push("proxy-groups:");
  push(lines, '- name: "AUTO"', 1);
  push(lines, "type: select", 2);
  push(lines, "proxies:", 2);
  push(lines, "  - DIRECT", 3);
  push(lines, "  - REJECT", 3);
  for (const p of proxies) {
    push(lines, `- "${escapeYamlString(p.name)}"`, 3);
  }
  lines.push("");

  // 最简单的 rules
  lines.push("rules:");
  lines.push("  - MATCH,AUTO");

  return lines.join("\n");
}

/* 对外导出的渲染函数 */
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

  /* 这里根据 UA 判断：Stash → proxies-only；其余 → 简单完整配置 */
  const ua = (meta.ua || "").toLowerCase();
  const isStash = ua.includes("stash");

  const body = isStash
    ? buildProxiesOnlyYaml(proxies, stats)
    : buildFullConfigYaml(proxies, stats);

  return {
    body,
    contentType: "text/yaml; charset=utf-8",
  };
}