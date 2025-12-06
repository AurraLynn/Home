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
//  5. 其它 client：保持 Converter 输出不动（比如 QX 行、Surge 行、Base64 订阅）
//
// 已支持的 client 名（由本文件负责识别与路由）：
//  - quantumultx：Quantumult X（UA 或 ?client=quantumultx）
//  - surge：Surge / Surfboard（UA 或 ?client=surge）
//  - clash：Clash / Clash.Meta / Mihomo / FlyClash（UA 或 ?client=clash）
//  - 空 / 其它：交给 Converter 默认处理（通常输出 Base64 订阅，给 Shadowrocket / v2rayNG 等吃）

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
  // 如果 client 为空，就不带 client 参数，让 Converter 用默认逻辑（Base64）

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

/* =========================================================
 * 工具：从 KV 记录里把「节点文本」抽出来
 * 兼容你之前保存的各种 JSON 结构
 * =======================================================*/

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

/* =========================================================
 * 工具：根据 UA 自动识别 client
 * 这里只负责大类，具体格式由 Converter + 各客户端 JS 处理
 * =======================================================*/

function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();
  if (!u) return "";

  // Clash / Clash.Meta / Mihomo / FlyClash
  if (u.includes("meta/") || u.includes(".meta")) return "clash";
  if (u.includes("clash") || u.includes("mihomo")) return "clash";

  // Surge / Surfboard
  if (u.includes("surge")) return "surge";

  // Quantumult X
  if (
    u.includes("quantumult%20x") ||
    u.includes("quantumult x") ||
    u.includes("quantumultx") ||
    u.includes("quanx")
  ) {
    return "quantumultx";
  }

  // 其它（Shadowrocket / v2rayNG / Sing-box 等）：不再单独识别，走 Base64
  return "";
}

/* =========================================================
 * Clash 完整配置（端口 + DNS + 分组 + 规则）
 * Converter 返回的是一个 proxies 段，这里把它包成完整 config
 * =======================================================*/

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
//  1）YAML 风格：- name: xxx
//  2）JSON 风格：- {"name":"xxx", ...}
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
