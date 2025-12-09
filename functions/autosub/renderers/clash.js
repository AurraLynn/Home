/*
  - 输入：
      解析后的 Node[]（至少包含 type / server / port）

  - 已支持协议：
      ss
      trojan
      hysteria2(hy2)

  - 输出：
      通用 Clash YAML，proxies 统一为 JSON 一行写法，例如：
        proxies:
          - {"name":"🇺🇸美国01","server":"pq.us1.xxx.com","port":35000,"ports":"35000-39000","mport":"35000-39000","udp":true,"skip-cert-verify":true,"sni":"www.apple.com","type":"hysteria2","auth":"xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"}

      各协议字段：
        ss:     name / type / server / port / cipher / password
        trojan: name / type / server / port / password / sni / skip-cert-verify
        hy2:    name / server / port / (可选 ports/mport) / udp / skip-cert-verify / sni / type / auth
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

  // 形如 ss://BASE64(method:pass)@host:port#name
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

  // 形如 ss://BASE64(method:pass@host:port)#name
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

/**
 * Node -> 简化后的 proxy 对象（只保留兼容字段）
 * 最终统一 JSON.stringify 输出，形如：
 *   {"name":"...","server":"...","port":35000,"udp":true,"skip-cert-verify":true,"sni":"www.apple.com","type":"hysteria2","auth":"xxxx"}
 */
function nodeToClashProxy(node) {
  if (!node) return null;

  const typeRaw = node.type || "";
  const type = typeRaw.toLowerCase();
  const server = node.server;
  const port = Number(node.port || 0);
  if (!server || !port) return null;

  const name = node.name || `${server}:${port}`;

  // ===== SS =====
  if (type === "ss") {
    const cipher = node.cipher || node.method;
    const password = node.password;

    if (!cipher || !password) return null;

    // 键顺序：name -> type -> server -> port -> cipher -> password
    const proxy = {
      name,
      type: "ss",
      server,
      port,
      cipher,
      password,
    };
    return proxy;
  }

  // ===== Trojan =====
  if (type === "trojan") {
    const password = node.password;
    if (!password) return null;

    // 键顺序：name -> type -> server -> port -> password -> sni -> skip-cert-verify
    const proxy = {
      name,
      type: "trojan",
      server,
      port,
      password,
    };

    if (node.sni) {
      proxy.sni = node.sni;
    }
    if (typeof node.skipCertVerify === "boolean") {
      proxy["skip-cert-verify"] = node.skipCertVerify;
    }

    return proxy;
  }

  // ===== Hysteria2 / hy2 =====
  if (type === "hysteria2" || type === "hy2") {
    let secret = node.auth || node.password || "";

    // 兜底从 uuid / user 拿
    if (!secret) {
      if (node.uuid) secret = String(node.uuid);
      else if (node.user) secret = String(node.user);
    }

    // 再兜底从 raw 里抠
    if (!secret && node.raw) {
      const raw = String(node.raw);

      let m =
        raw.match(/^hysteria2:\/\/([^@?#]+)@/i) ||
        raw.match(/^hy2:\/\/([^@?#]+)@/i);
      if (m && m[1]) {
        try {
          secret = decodeURIComponent(m[1]);
        } catch {
          secret = m[1];
        }
      }

      if (!secret) {
        const m2 = raw.match(
          /[?&](?:password|passwd|auth|auth_str|psk)=([^&#]+)/i
        );
        if (m2 && m2[1]) {
          try {
            secret = decodeURIComponent(m2[1]);
          } catch {
            secret = m2[1];
          }
        }
      }
    }

    if (!secret) return null;

    // 同步回 Node，方便其它渲染器使用
    node.password = node.password || secret;
    if (!node.auth) node.auth = secret;

    // ★ 按机场写法：
    //   { name, server, port, ports, mport, udp, skip-cert-verify, sni, type: "hysteria2", auth }
    const proxy = {
      name,
      server,
      port,
    };

    // 如果 Node 有端口段就带上（字符串形式如 "35000-39000"）
    if (node.ports) proxy.ports = String(node.ports);
    if (node.mport) proxy.mport = String(node.mport);

    proxy.udp = true;

    proxy["skip-cert-verify"] =
      typeof node.skipCertVerify === "boolean" ? node.skipCertVerify : true;

    if (node.sni) {
      proxy.sni = node.sni;
    }

    proxy.type = "hysteria2";
    proxy.auth = secret;

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
      // 统一 JSON 一行写法
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
      lines.push("      - " + JSON.stringify(name));
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
