/*
  - 输入：
      解析后的 Node[]（至少包含 type / server / port）

  - 已支持协议：
      ss
      trojan
      hysteria2(hy2)

  - 输出：
      Clash / Mihomo / Meta / Stash 通用 YAML
      用法示例：/autosub?id=你的id&client=clash
*/

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

function parseSSRaw(raw) {
  const s = String(raw || "").trim();
  if (!s.startsWith("ss://")) return null;

  let rest = s.slice(5);

  let name = "";
  const hashIndex = rest.indexOf("#");
  if (hashIndex >= 0) {
    name = decodeURIComponent(rest.slice(hashIndex + 1));
    rest = rest.slice(0, hashIndex);
  }

  const qIndex = rest.indexOf("?");
  if (qIndex >= 0) rest = rest.slice(0, qIndex);

  if (rest.includes("@")) {
    const [b64Part, hostPart] = rest.split("@");
    const decoded = b64DecodeUrlSafe(b64Part);
    const [cipher, password] = decoded.split(":");
    const [server, portStr] = hostPart.split(":");
    const port = Number(portStr);
    if (!cipher || !password || !server || !port) return null;
    return {
      type: "ss",
      server,
      port,
      cipher,
      password,
      name: name || `${server}:${port}`,
    };
  }

  const decoded = b64DecodeUrlSafe(rest);
  if (decoded && decoded.includes("@")) {
    const [left, right] = decoded.split("@");
    const [cipher, password] = left.split(":");
    const [server, portStr] = right.split(":");
    const port = Number(portStr);
    if (!cipher || !password || !server || !port) return null;
    return {
      type: "ss",
      server,
      port,
      cipher,
      password,
      name: name || `${server}:${port}`,
    };
  }

  return null;
}

/** 简单的 YAML 字符串转义（只用在我们手控的 config 字段上） */
function yamlQuote(value) {
  if (value === undefined || value === null) return '""';
  const s = String(value);
  return '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function nodeToClashProxy(node) {
  if (!node) return null;

  // ===== SS =====
  if (node.type === "ss") {
    if (node.server && node.port && (node.cipher || node.method) && node.password) {
      return {
        name: node.name || `${node.server}:${node.port}`,
        type: "ss",
        server: node.server,
        port: Number(node.port),
        cipher: node.cipher || node.method,
        password: node.password,
        udp: true,
        plugin: node.plugin,
        pluginOpts: node.pluginOpts,
      };
    }

    if (node.raw) {
      const p = parseSSRaw(node.raw);
      if (p) {
        return {
          name: p.name,
          type: "ss",
          server: p.server,
          port: p.port,
          cipher: p.cipher,
          password: p.password,
          udp: true,
        };
      }
    }
  }

  // ===== Trojan =====
  if (node.type === "trojan") {
    const server = node.server;
    const port = Number(node.port || 0);
    const password = node.password;

    if (!server || !port || !password) return null;

    const proxy = {
      name: node.name || `${server}:${port}`,
      type: "trojan",
      server,
      port,
      password,
      tls: true,
      udp: true,
    };

    if (node.sni) proxy.sni = node.sni;
    if (typeof node.skipCertVerify === "boolean") {
      proxy.skipCertVerify = node.skipCertVerify ? true : false;
    }

    return proxy;
  }

  // ===== Hysteria2 / hy2 =====
  if (node.type === "hysteria2" || node.type === "hy2") {
    const server = node.server;
    const port = Number(node.port || 0);

    let password = node.password || node.auth || "";

    if (!password) {
      if (node.uuid) password = String(node.uuid);
      else if (node.user) password = String(node.user);
    }

    if (!password && node.raw) {
      const raw = String(node.raw);

      let m =
        raw.match(/^hysteria2:\/\/([^@?#]+)@/i) ||
        raw.match(/^hy2:\/\/([^@?#]+)@/i);
      if (m && m[1]) {
        try {
          password = decodeURIComponent(m[1]);
        } catch {
          password = m[1];
        }
      }

      if (!password) {
        const m2 = raw.match(
          /[?&](?:password|passwd|auth|auth_str|psk)=([^&#]+)/i
        );
        if (m2 && m2[1]) {
          try {
            password = decodeURIComponent(m2[1]);
          } catch {
            password = m2[1];
          }
        }
      }
    }

    if (!server || !port || !password) return null;

    node.password = node.password || password;
    if (!node.auth) node.auth = password;

    const proxy = {
      name: node.name || `${server}:${port}`,
      type: "hysteria2",
      server,
      port,
      password,
      udp: true,
      fastOpen: true,
      skipCertVerify:
        typeof node.skipCertVerify === "boolean" ? !!node.skipCertVerify : undefined,
      sni: node.sni,
      obfs: node.obfs,
      obfsPassword: node.obfsPassword,
      alpn: node.alpn,
      up: node.up,
      down: node.down,
      ports: node.ports,
    };

    return proxy;
  }

  return null;
}

/** 把单个 proxy 对象转成 YAML（块状写法），缩进两个空格起步 */
function dumpProxyYaml(p) {
  const lines = [];
  lines.push(`  - name: ${yamlQuote(p.name)}`);
  lines.push(`    type: ${p.type}`);
  lines.push(`    server: ${yamlQuote(p.server)}`);
  lines.push(`    port: ${Number(p.port)}`);

  if (p.type === "ss") {
    if (p.cipher) lines.push(`    cipher: ${yamlQuote(p.cipher)}`);
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
    if (typeof p.udp === "boolean") lines.push(`    udp: ${p.udp ? "true" : "false"}`);
    if (p.plugin) lines.push(`    plugin: ${yamlQuote(p.plugin)}`);
    if (p.pluginOpts) {
      // 简单一点：用字符串承载，复杂 plugin-opts 就不在这里展开了
      lines.push(`    plugin-opts: ${yamlQuote(JSON.stringify(p.pluginOpts))}`);
    }
  } else if (p.type === "trojan") {
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
    lines.push(`    tls: true`);
    if (typeof p.udp === "boolean") lines.push(`    udp: ${p.udp ? "true" : "false"}`);
    if (p.sni) lines.push(`    sni: ${yamlQuote(p.sni)}`);
    if (typeof p.skipCertVerify === "boolean") {
      lines.push(`    skip-cert-verify: ${p.skipCertVerify ? "true" : "false"}`);
    }
  } else if (p.type === "hysteria2") {
    if (p.password) lines.push(`    password: ${yamlQuote(p.password)}`);
    if (typeof p.udp === "boolean") lines.push(`    udp: ${p.udp ? "true" : "false"}`);
    if (typeof p.fastOpen === "boolean") {
      lines.push(`    fast-open: ${p.fastOpen ? "true" : "false"}`);
    }
    if (typeof p.skipCertVerify === "boolean") {
      lines.push(`    skip-cert-verify: ${p.skipCertVerify ? "true" : "false"}`);
    }
    if (p.sni) lines.push(`    sni: ${yamlQuote(p.sni)}`);
    if (p.obfs) lines.push(`    obfs: ${yamlQuote(p.obfs)}`);
    if (p.obfsPassword) {
      lines.push(`    obfs-password: ${yamlQuote(p.obfsPassword)}`);
    }
    if (p.alpn) {
      const arr = String(p.alpn)
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      if (arr.length) {
        lines.push(`    alpn:`);
        for (const a of arr) {
          lines.push(`      - ${yamlQuote(a)}`);
        }
      }
    }
    if (p.up) lines.push(`    up: ${yamlQuote(p.up)}`);
    if (p.down) lines.push(`    down: ${yamlQuote(p.down)}`);
    if (p.ports) lines.push(`    ports: ${yamlQuote(p.ports)}`);
  }

  return lines.join("\n");
}

export function renderClash(nodes = []) {
  const proxies = [];

  for (const n of nodes) {
    const p = nodeToClashProxy(n);
    if (p) proxies.push(p);
  }

  const names = proxies.map((p) => p.name);

  const lines = [];
  lines.push("port: 7890");
  lines.push("socks-port: 7891");
  lines.push("mode: Rule");
  lines.push("allow-lan: true");
  lines.push("log-level: info");
  lines.push("");
  lines.push("dns:");
  lines.push("  enable: true");
  lines.push("  listen: 0.0.0.0:53");
  lines.push("  ipv6: false");
  lines.push("  nameserver:");
  lines.push("    - 223.5.5.5");
  lines.push("    - 223.6.6.6");
  lines.push("");
  lines.push("proxies:");

  if (proxies.length === 0) {
    lines.push("  # no supported proxies parsed yet");
  } else {
    for (const p of proxies) {
      lines.push(dumpProxyYaml(p));
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
    for (const name of names) {
      lines.push(`      - ${yamlQuote(name)}`);
    }
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
