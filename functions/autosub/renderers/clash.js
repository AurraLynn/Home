/*
  - 输入：
      解析后的 Node[]（至少包含 type / server / port）

  - 已支持协议：
      ss
      trojan
      hysteria2(hy2)

  - 输出：
      Clash / Mihomo / Meta / Stash 通用 YAML
      搭配：/autosub?id=你的id&client=clash 使用
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

function nodeToClashProxy(node) {
  if (!node) return null;

  // SS
  if (node.type === "ss") {
    if (node.server && node.port && (node.cipher || node.method) && node.password) {
      const proxy = {
        name: node.name || `${node.server}:${node.port}`,
        type: "ss",
        server: node.server,
        port: Number(node.port),
        cipher: node.cipher || node.method,
        password: node.password,
        udp: true,
      };

      if (node.plugin) proxy.plugin = node.plugin;
      if (node.pluginOpts) proxy["plugin-opts"] = node.pluginOpts;

      return proxy;
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

  // Trojan
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
      proxy["skip-cert-verify"] = node.skipCertVerify ? true : false;
    }

    return proxy;
  }

  // Hysteria2 / hy2
  if (node.type === "hysteria2" || node.type === "hy2") {
    const server = node.server;
    const port = Number(node.port || 0);
    const password = node.password;

    if (!server || !port || !password) return null;

    const proxy = {
      name: node.name || `${server}:${port}`,
      type: "hysteria2",
      server,
      port,
      auth: password,
      udp: true,
      "fast-open": true,
    };

    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify ? true : false;
    }

    if (node.sni) {
      proxy.sni = node.sni;
    }

    if (node.obfs) {
      proxy.obfs = node.obfs;
    }
    if (node.obfsPassword) {
      proxy["obfs-password"] = node.obfsPassword;
    }

    if (node.alpn) {
      const arr = String(node.alpn)
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      if (arr.length) proxy.alpn = arr;
    }

    if (node.up) proxy.up = node.up;
    if (node.down) proxy.down = node.down;
    if (node.ports) proxy.ports = node.ports;

    return proxy;
  }

  return null;
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
      lines.push("  - " + JSON.stringify(p));
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
      lines.push(`      - "${name}"`);
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
