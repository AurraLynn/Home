/*
  - 输入：
      解析后的 Node[]（至少包含 type / server / port）

  - 已支持协议：
      ss
      trojan
      hysteria2(hy2)

  - 输出：
      通用 Clash YAML，proxies 部分统一为 JSON 一行写法：
        proxies:
          - {"type":"hysteria2","name":"...","server":"...","port":30102,"password":"...","sni":"...","skip-cert-verify":true,"tfo":true}

  - 兼容性策略：
      只保留各协议最基本、绝大部分客户端都支持的字段：
        ss:       type / name / server / port / cipher / password
        trojan:   type / name / server / port / password / sni / skip-cert-verify
        hy2:      type / name / server / port / password / sni / skip-cert-verify / tfo
      自动丢弃：
        udp / fast-open / alpn / up / down / ports / plugin / plugin-opts 等
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

/**
 * Node -> 简化后的 proxy 对象，只包含各协议兼容性最高的字段。
 * 返回的对象会直接 JSON.stringify 输出到 YAML：
 *   proxies:
 *     - {"type":"...","name":"...","server":"...","port":1234,...}
 */
function nodeToClashProxy(node) {
  if (!node) return null;

  const type = (node.type || "").toLowerCase();
  const server = node.server;
  const port = Number(node.port || 0);
  const name = node.name || (server && port ? `${server}:${port}` : "");

  if (!server || !port) return null;

  // ===== SS =====
  if (type === "ss") {
    const cipher = node.cipher || node.method;
    const password = node.password;

    if (!cipher || !password) return null;

    return {
      type: "ss",
      name,
      server,
      port,
      cipher,
      password,
    };
  }

  // ===== Trojan =====
  if (type === "trojan") {
    const password = node.password;
    if (!password) return null;

    const out = {
      type: "trojan",
      name,
      server,
      port,
      password,
    };

    if (node.sni) {
      out.sni = node.sni;
    }

    // 绝大多数客户端都支持 skip-cert-verify
    if (typeof node.skipCertVerify === "boolean") {
      out["skip-cert-verify"] = node.skipCertVerify;
    }

    return out;
  }

  // ===== Hysteria2 / hy2 =====
  if (type === "hysteria2" || type === "hy2") {
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

    if (!password) return null;

    // 同步回 Node，方便其他渲染器也用到
    node.password = node.password || password;
    if (!node.auth) node.auth = password;

    const out = {
      type: "hysteria2",
      name,
      server,
      port,
      password,
      // 这两个是你验证过「可以用」的字段：
      // {"skip-cert-verify":true,"tfo":true}
      "skip-cert-verify":
        typeof node.skipCertVerify === "boolean" ? node.skipCertVerify : true,
      tfo: true,
    };

    if (node.sni) {
      out.sni = node.sni;
    }

    // 其它：udp / fast-open / alpn / up / down / ports / obfs ...
    // 为了兼容 FIClash / NekoBox / FlyClash，全部省略

    return out;
  }

  return null;
}

/**
 * 统一渲染成 Clash YAML，proxies 使用 JSON 一行写法，
 * 适配 Clash Meta / Meya / FIClash / NekoBox / FlyClash 等。
 */
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
      // 这里用 JSON.stringify 简单包一层引号
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
