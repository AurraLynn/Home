// functions/api/sub/index.js
//
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 作用：
//  1. 从 KV: Paste 读取原始内容
//  2. 决定 client（优先 query，其次 UA 自动识别）
//  3. 把原始文本 POST 给 /api/sub/Converter?client=xxx 做节点解析与转换
//  4. 如果是 Clash 系（client=clash），在 Converter 返回的 proxies 段外面再包上完整配置：
//     - 端口 + 阿里 DNS
//     - proxy-groups: 🐹Lyn · Node
//     - 简单规则（GEOIP,LAN / GEOIP,CN / MATCH）
//  5. 其它 client：保持 Converter 输出不动（比如 QX 行、Base64 订阅）
//
// 已支持的 client 名：
//  - quantumultx：Quantumult X
//  - clash：Clash / Clash.Meta / Mihomo / FlyClash
//  - 其它 / 空：交给 Converter 默认处理（通常输出 Base64 订阅）

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

  // ===== 1. 从 KV 里读取原始内容 =====
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

  // ===== 3. 拼接 Converter 地址 =====
  const origin = url.origin;
  let converterUrl = `${origin}/api/sub/Converter`;
  if (client) {
    converterUrl = `${origin}/api/sub/Converter?client=${encodeURIComponent(
      client
    )}`;
  }

  // 把原始内容 POST 给 Converter
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

  // ===== 4. Clash / Mihomo：套完整配置 =====
  if (client === "clash") {
    convertedText = buildClashFullConfig(convertedText);
  }

  // ===== 5. 返回结果 =====
  const headers = new Headers();
  headers.set("content-type", "text/plain; charset=utf-8");

  return new Response(convertedText, {
    status: 200,
    headers,
  });
}

/* ========== 从 KV 记录里提取节点文本 ========== */

function extractContentFromRecord(stored) {
  if (!stored) return "";

  const trimmed = stored.trim();
  const firstChar = trimmed[0];

  // 看起来不像 JSON，就当纯文本
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

    // 实在找不到就整段 JSON 当原始文本
    return stored;
  } catch (_e) {
    return stored;
  }
}

/* ========== UA → client 名 ========== */

function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();
  if (!u) return "";

  // Clash / Clash.Meta / Mihomo / FlyClash
  if (u.includes("meta/") || u.includes(".meta")) return "clash";
  if (u.includes("clash") || u.includes("mihomo")) return "clash";

  // Quantumult X（如果不带 ?client=quantumultx，用 UA 也能识别）
  if (
    u.includes("quantumult%20x") ||
    u.includes("quantumult x") ||
    u.includes("quantumultx") ||
    u.includes("quanx")
  ) {
    return "quantumultx";
  }

  // 其它（Surge / Shadowrocket / v2rayNG / Sing-box 等）：走 Base64
  return "";
}

/* ========== Clash 完整配置包装 ========== */

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

// 从 Converter 返回的文本里抓出所有节点名称
// 兼容：
//  1）- name: xxx
//  2）- {"name":"xxx", ...}
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
        // 忽略 JSON 解析错误
      }
    }
  }

  return names;
}

// 把 proxies 段包装成完整 Clash 配置
function buildClashFullConfig(nodesYaml) {
  const names = extractClashProxyNames(nodesYaml);

  // 没解析出节点名，就原样返回（至少还能被 Clash 直接当片段用）
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
