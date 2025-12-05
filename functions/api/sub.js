// functions/api/sub.js
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 1. 从 KV: Paste 读取原始内容
// 2. 决定 client（优先 query，其次 UA 自动识别）
// 3. 调用 /api/node-convert?client=xxx 做节点转换
// 4. 对 Clash / Mihomo 自动包一层完整配置（含阿里 DNS + 简单分组）
// 5. 其它客户端：保持 node-convert 输出不变（如 v2ray Base64、Surge 行、QX 行等）

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

  // ===== 1. 从 KV: Paste 读取内容 =====
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

  // ===== 2. 决定 client 类型 =====
  if (!client) {
    client = detectClientFromUA(ua);
  }
  if (!client) {
    // 识别不了：默认走 v2ray Base64 订阅（安卓兼容性最好）
    client = "v2ray";
  }

  // ===== 3. 调用 /api/node-convert 做节点转换 =====
  const origin = url.origin;
  const convertUrl = `${origin}/api/node-convert?client=${encodeURIComponent(
    client
  )}`;

  const res = await fetch(convertUrl, {
    method: "POST",
    body: raw,
  });

  const convertedText = await res.text();

  if (!res.ok) {
    return new Response(convertedText || "convert error", {
      status: res.status,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  let outText = convertedText;

  // ===== 4. 对 Clash / Mihomo 自动套模板，生成完整配置 =====
  // client=clash：Clash / Clash Meta / Mihomo / FlyClash 统一用这一套
  if (client === "clash") {
    outText = buildClashFullConfig(convertedText);
  }

  // ===== 5. 根据 client 决定返回类型 =====
  const headers = new Headers();

  if (client === "sing-box") {
    headers.set("content-type", "application/json; charset=utf-8");
  } else {
    headers.set("content-type", "text/plain; charset=utf-8");
  }

  // 如需最保险避免 BOM/压缩，可以改成 TextEncoder + Content-Encoding: identity
  return new Response(outText, {
    status: 200,
    headers,
  });
}

// ===== 工具：从 KV 记录提取节点文本 =====
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

    // 实在找不到，就把整个 JSON 再当文本
    return stored;
  } catch (_e) {
    return stored;
  }
}

// ===== 工具：UA → client 名 =====

// 安全解码（有些 UA 里面带 %20 之类）
function safeDecodeURIComponent(str) {
  try {
    return decodeURIComponent(str);
  } catch (_e) {
    return str || "";
  }
}

function detectClientFromUA(ua) {
  const raw = ua || "";
  const u = raw.toLowerCase(); // 原始 UA
  const uDec = safeDecodeURIComponent(raw).toLowerCase(); // decode 后 UA

  // 把两种形式拼一起，统一匹配（解决 Quantumult%20X）
  const h = u + " " + uDec;

  // FlyClash / Clash Meta：meta/0.2.0.9.Meta 之类
  if (h.includes("meta/") || h.includes(".meta")) return "clash";

  // Clash 系：Clash, Mihomo, Clash for Windows, Clash for Android 等
  if (h.includes("clash") || h.includes("mihomo")) return "clash";

  // Stash
  if (h.includes("stash")) return "stash";

  // Surge
  if (h.includes("surge")) return "surge";

  // Quantumult X：
  // 可能出现在：Quantumult%20X / Quantumult X / QuantumultX / QuanX
  if (
    h.includes("quantumult%20x") ||
    h.includes("quantumult x") ||
    h.includes("quantumultx") ||
    h.includes("quanx")
  ) {
    return "quantumultx";
  }

  // 老 Quantumult（如果你以后要用，可以单独分支）
  if (h.includes("quantumult")) return "quantumult";

  // Sing-box
  if (h.includes("sing-box") || h.includes("singbox")) return "sing-box";

  // Egern
  if (h.includes("egern")) return "egern";

  // Loon
  if (h.includes("loon")) return "loon";

  // Surfboard
  if (h.includes("surfboard")) return "surfboard";

  // V2Ray / V2RayNG / Hiddify / Nekobox：统一用 v2ray Base64 订阅
  if (h.includes("v2ray") || h.includes("v2rayng")) return "v2ray";
  if (h.includes("hiddify")) return "v2ray";
  if (h.includes("nekobox")) return "v2ray";

  // 不再对 Shadowrocket 做专门处理：让它走 v2ray Base64
  // if (h.includes("shadowrocket")) return "v2ray";

  // 识别不了：交给上层默认 v2ray 处理
  return "";
}

// ===== Clash / Mihomo 完整配置相关 =====

// 简化版基准配置：端口 + 阿里 DNS
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

// 从 node-convert 返回的 YAML 里抓出所有节点名称
function extractClashProxyNames(nodesYaml) {
  const lines = (nodesYaml || "").split(/\r?\n/);
  const names = [];
  for (const line of lines) {
    const m = line.match(/^\s*-\s*name:\s*(.+)\s*$/);
    if (m) {
      let name = m[1].trim();
      // 去掉包裹引号
      if (
        (name.startsWith('"') && name.endsWith('"')) ||
        (name.startsWith("'") && name.endsWith("'"))
      ) {
        name = name.slice(1, -1);
      }
      names.push(name);
    }
  }
  return names;
}

// 把节点列表塞进完整 Clash 配置
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