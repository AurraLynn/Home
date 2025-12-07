// functions/api/sub/index.js
// 
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 1. 从 KV: Paste 读取原始内容
// 2. 决定 client：优先 query，其次 UA 自动识别
// 3. 调用 /api/sub/Converter?client=xxx 做节点转换
// 4. 对 Clash / Mihomo：在 Converter 返回的 proxies 段基础上，自动包一份完整配置（含端口 + 阿里 DNS + 分组 + 规则）
// 5. 其它客户端：保持 Converter 输出不变（例如 Quantumult X 行、Surge 行、Stash proxies 段、Base64 订阅）
//
// 已支持的 client 名：
// - quantumultx：Quantumult X
// - surge：Surge
// - clash：Clash / Mihomo / FlyClash（meta/...）
// - stash：Stash（只返回 proxies 段，由 /api/sub/Stash 生成）
// - 其它（shadowrocket / v2rayng 等）：默认走 Base64 订阅

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

  // ===== 1. 读取 KV: Paste =====
  if (!env.Paste) {
    return new Response("KV namespace `Paste` not bound", { status: 500 });
  }

  const stored = await env.Paste.get(id);
  if (!stored) {
    return new Response("not found", { status: 404 });
  }

  const raw = extractContentFromRecord(stored);
  if (!raw || !raw.trim()) {
    return new Response("empty content", { status: 404 });
  }

  // ===== 2. 决定 client：优先 query，其次 UA 自动识别 =====
  if (!client) {
    client = detectClientFromUA(ua);
  }

  const origin = url.origin;

  // ===== 3. 调用 /api/sub/Converter 做转换 =====
  let converterUrl = `${origin}/api/sub/Converter`;

  if (client === "quantumultx") {
    converterUrl = `${origin}/api/sub/Converter?client=quantumultx`;
  } else if (client === "surge") {
    converterUrl = `${origin}/api/sub/Converter?client=surge`;
  } else if (client === "clash") {
    converterUrl = `${origin}/api/sub/Converter?client=clash`;
  } else if (client === "stash") {
    converterUrl = `${origin}/api/sub/Converter?client=stash`;
  } else if (client) {
    // 其它 client（例如 shadowrocket / v2rayng 等），透传给 Converter，由 Converter 决定行为
    converterUrl = `${origin}/api/sub/Converter?client=${encodeURIComponent(
      client
    )}`;
  }
  // 如果 client 为空，就不带 client 参数，让 Converter 默认输出 Base64

  const res = await fetch(converterUrl, {
    method: "POST",
    body: raw,
  });

  let convertedText = await res.text();

  if (!res.ok) {
    return new Response(convertedText || "convert error", {
      status: res.status,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // ===== 4. Clash / Mihomo：自动包完整配置 =====
  if (client === "clash") {
    convertedText = buildClashFullConfig(convertedText);
  }

  // 当前所有 client 都返回 text/plain
  const headers = new Headers();
  headers.set("content-type", "text/plain; charset=utf-8");

  return new Response(convertedText, {
    status: 200,
    headers,
  });
}

/* ========== 工具：从 KV 记录中提取节点文本 ========== */

function extractContentFromRecord(stored) {
  if (!stored) return "";

  const trimmed = stored.trim();
  const firstChar = trimmed[0];

  // 看起来不像 JSON，就按纯文本
  if (firstChar !== "{" && firstChar !== "[") {
    return stored;
  }

  try {
    const obj = JSON.parse(trimmed);

    if (typeof obj.content === "string") return obj.content;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.body === "string") return obj.body;
    if (typeof obj.raw === "string") return obj.raw;
    if (typeof obj.nodeContent === "string") return obj.nodeContent;
    if (typeof obj.data === "string") return obj.data;

    // 实在找不到，就把整个 JSON 再当成原始文本
    return stored;
  } catch (_e) {
    return stored;
  }
}

/* ========== 工具：UA → client 名 ========== */

function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();
  if (!u) return "";

  // 1) FlyClash / Clash Meta：meta/0.2.0.9.Meta 一类
  if (u.includes("meta/") || u.includes(".meta")) return "clash";

  // 2) Stash：有些 UA 同时带 Stash 和 Clash，这里让 Stash 优先
  //    例如："Stash/3.2.4 Clash/1.9.0"
  if (u.includes("stash")) return "stash";

  // 3) Clash 系：Clash, Mihomo, Clash for Windows, Clash for Android 等
  if (u.includes("clash") || u.includes("mihomo")) return "clash";

  // 4) Surge
  if (u.includes("surge")) return "surge";

  // 5) Quantumult X：Quantumult%20X / Quantumult X / QuantumultX / QuanX
  if (
    u.includes("quantumult%20x") ||
    u.includes("quantumult x") ||
    u.includes("quantumultx") ||
    u.includes("quanx")
  ) {
    return "quantumultx";
  }

  // 6) Shadowrocket / 其它客户端：不再单独识别，默认走 Base64 通用订阅
  return "";
}

/* ========== Clash / Mihomo 完整配置相关 ========== */

// 简化版：端口 + 阿里 DNS
const CLASH_BASE_HEADER = `port: 7890
socks-port: 7891
mode: Rule
allow-lan: true
log-level: info

dns:
  enable: true
  listen: 0.0.0.0:53
  ipv6: false
  nameserver:
    - 223.5.5.5
    - 223.6.6.6
`;

// 从 /api/sub/Clash 返回的 proxies 段中提取所有节点名称
// 兼容两种格式：
// 1）- name: xxx
// 2）- {"name":"xxx", ...}
function extractClashProxyNames(nodesYaml) {
  const lines = (nodesYaml || "").split(/\r?\n/);
  const names = [];

  for (const line of lines) {
    const l = line.trim();
    if (!l.startsWith("-")) continue;

    // 格式 1：- name: xxx
    let m = l.match(/^\-\s*name:\s*(.+)\s*$/);
    if (m) {
      let name = m[1].trim();
      if (
        (name.startsWith('"') && name.endsWith('"')) ||
        (name.startsWith("'") && name.endsWith("'"))
      ) {
        name = name.slice(1, -1);
      }
      names.push(name);
      continue;
    }

    // 格式 2：- {"name":"xxx", ...}
    m = l.match(/^\-\s*(\{.*"name"\s*:\s*".*"\s*.*\})\s*$/);
    if (m) {
      try {
        const obj = JSON.parse(m[1]);
        if (obj && typeof obj.name === "string") {
          names.push(obj.name);
        }
      } catch (_e) {
        // ignore JSON parse error
      }
    }
  }

  return names;
}

// 把 proxies 段塞进完整 Clash 配置（含分组与规则）
function buildClashFullConfig(nodesYaml) {
  const names = extractClashProxyNames(nodesYaml);

  // 没解析出节点名就原样返回（至少还能用）
  if (!names.length) {
    return nodesYaml;
  }

  const groupName = "🐹Lyn · Node";

  const groupLines = [];
  groupLines.push("proxy-groups:");
  groupLines.push(`  - name: "${groupName}"`);
  groupLines.push("    type: select");
  groupLines.push("    proxies:");
  for (const n of names) {
    groupLines.push('      - "' + n.replace(/"/g, '\\"') + '"');
  }
  groupLines.push("");
  groupLines.push("rules:");
  groupLines.push("  - GEOIP,LAN,DIRECT");
  groupLines.push("  - GEOIP,CN,DIRECT");
  groupLines.push("  - MATCH," + groupName);

  const groupSection = groupLines.join("\n");

  return (
    CLASH_BASE_HEADER +
    "\n" +
    nodesYaml.trim() +
    "\n\n" +
    groupSection +
    "\n"
  );
}
