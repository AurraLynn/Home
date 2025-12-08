/**
 * Clash Renderer v1
 * - 输出一个“最小可用主配置” + proxies + proxy-groups + rules
 * - 目前优先支持 ss
 * - 如果 Parser 还没把 ss 解析成字段，这里会尝试从 raw ss:// 自行解析
 *
 * 你给的目标样式：
 * port/socks-port/mode/allow-lan/log-level/dns
 * proxies: - {"type":"ss",...}
 * proxy-groups:  - name: "🐹Lyn · Node" ...
 * rules: ...
 */

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).replace(/-/g, "+").replace(/_/g, "/");
  // padding
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

/**
 * 解析 ss://
 * 兼容常见形态：
 *  1) ss://BASE64(method:password)@host:port#name
 *  2) ss://BASE64(method:password@host:port)#name
 *  3) ss://method:password@host:port#name
 *
 * 返回 { type, server, port, cipher, password, name }
 */
function parseSSRaw(raw) {
  const s = String(raw || "").trim();
  if (!s.startsWith("ss://")) return null;

  // 去掉 ss://
  let rest = s.slice(5);

  // name (fragment)
  let name = "";
  const hashIndex = rest.indexOf("#");
  if (hashIndex >= 0) {
    name = decodeURIComponent(rest.slice(hashIndex + 1));
    rest = rest.slice(0, hashIndex);
  }

  // 丢弃 query（如果有）
  const qIndex = rest.indexOf("?");
  if (qIndex >= 0) {
    rest = rest.slice(0, qIndex);
  }

  // 情况 A：已经是明文 method:pass@host:port
  if (rest.includes("@") && rest.includes(":") && !/^[A-Za-z0-9\-_+/=]+$/.test(rest.split("@")[0])) {
    // method:password@host:port
    const [left, right] = rest.split("@");
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

  // 情况 B：BASE64(method:pass)@host:port
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

  // 情况 C：BASE64(method:pass@host:port)
  const decoded = b64DecodeUrlSafe(rest);
  if (decoded.includes("@")) {
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
 * 把 Node 转成 Clash proxy 对象
 * - 优先使用 Parser 产出的结构化字段
 * - 否则尝试从 raw 解析 ss
 */
function nodeToClashProxy(node) {
  if (!node) return null;

  // 如果 Parser 已经做了结构化
  if (node.type === "ss" && node.server && node.port && node.cipher && node.password) {
    return {
      type: "ss",
      server: node.server,
      port: Number(node.port),
      cipher: node.cipher,
      password: node.password,
      name: node.name || node.tag || "SS",
    };
  }

  // 退回 raw 解析
  if (node.type === "ss" && node.raw) {
    const p = parseSSRaw(node.raw);
    if (!p) return null;

    return {
      type: "ss",
      server: p.server,
      port: p.port,
      cipher: p.cipher,
      password: p.password,
      name: p.name,
    };
  }

  // 你后面扩展 vmess/vless/trojan/hy2 时在这里加
  return null;
}

/**
 * 输出你要的“简单包一层配置”
 */
export function renderClash(nodes = []) {
  const proxies = [];

  for (const n of nodes) {
    // 目前只输出 ss
    if (n?.type !== "ss") continue;

    const p = nodeToClashProxy(n);
    if (p) proxies.push(p);
  }

  // 如果一个都没解析出来，也保证 YAML 结构不炸
  const names = proxies.map(p => p.name);

  const lines = [];

  // ===== 基础主配置（按你给的示例） =====
  lines.push(`port: 7890`);
  lines.push(`socks-port: 7891`);
  lines.push(`mode: Rule`);
  lines.push(`allow-lan: true`);
  lines.push(`log-level: info`);
  lines.push(``);
  lines.push(`dns:`);
  lines.push(`  enable: true`);
  lines.push(`  listen: 0.0.0.0:53`);
  lines.push(`  ipv6: false`);
  lines.push(`  nameserver:`);
  lines.push(`    - 223.5.5.5`);
  lines.push(`    - 223.6.6.6`);
  lines.push(``);
  lines.push(`proxies:`);

  // ===== proxies 区 =====
  if (proxies.length === 0) {
    lines.push(`  # no supported proxies parsed yet`);
  } else {
    for (const p of proxies) {
      // 你喜欢的 JSON 内联风格
      lines.push(`  - ${JSON.stringify(p)}`);
    }
  }

  // ===== proxy-groups =====
  lines.push(``);
  lines.push(`proxy-groups:`);
  lines.push(`  - name: "🐹Lyn · Node"`);
  lines.push(`    type: select`);
  lines.push(`    proxies:`);

  if (names.length === 0) {
    lines.push(`      - DIRECT`);
  } else {
    for (const name of names) {
      lines.push(`      - "${name}"`);
    }
  }

  // ===== rules =====
  lines.push(``);
  lines.push(`rules:`);
  lines.push(`  - GEOIP,LAN,DIRECT`);
  lines.push(`  - GEOIP,CN,DIRECT`);
  lines.push(`  - MATCH,🐹Lyn · Node`);

  return {
    body: lines.join("\n"),
    contentType: "text/yaml; charset=utf-8",
  };
}
