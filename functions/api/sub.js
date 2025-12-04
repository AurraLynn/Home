// functions/api/sub.js
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 1. 从 KV: Paste 读取原始内容
// 2. 调用 /api/node-convert?client=xxx 转换成各客户端格式
// 3. 对 Clash / Mihomo 等客户端，自动包上一份完整配置（含阿里 DNS + 简单分流）

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
    // 识别不了：默认走 v2ray Base64 订阅，安卓兼容性最好
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
    return new Response(convertedText || "convert error", { status: res.status });
  }

  let outText = convertedText;

  // ===== 4. 对 Clash / Mihomo 自动套模板，生成完整配置 =====
  // 这里以 client=clash 为主，Clash / Clash Meta / Mihomo 都用这一套
  if (client === "clash") {
    outText = buildClashFullConfig(convertedText);
  }

  const headers = new Headers();

  if (client === "sing-box") {
    headers.set("content-type", "application/json; charset=utf-8");
  } else {
    headers.set("content-type", "text/plain; charset=utf-8");
  }

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
  } catch (e) {
    return stored;
  }
}

// ===== 工具：UA → client 名 =====
// UA → client
function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();

  // ✅ 先特殊处理 FlyClash
  if (u.includes("flyclash")) return "clash";

  // 下面这些保持不变
  if (u.includes("clash") || u.includes("mihomo")) return "clash";
  if (u.includes("stash")) return "stash";
  if (u.includes("surge")) return "surge";
  if (u.includes("shadowrocket")) return "shadowrocket";
  if (u.includes("quantumult x") || u.includes("quantumult_x"))
    return "quantumultx";
  if (u.includes("sing-box") || u.includes("singbox")) return "sing-box";
  if (u.includes("egern")) return "egern";
  if (u.includes("loon")) return "loon";
  if (u.includes("surfboard")) return "surfboard";
  if (u.includes("v2ray") || u.includes("v2rayng")) return "v2ray";

  return "";
}

// ===== Clash / Mihomo 完整配置相关 =====

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

// 从 node-convert 返回的 YAML 里抓出所有节点名称
function extractClashProxyNames(nodesYaml) {
  const lines = (nodesYaml || "").split(/\r?\n/);
  const names = [];
  for (const line of lines) {
    const m = line.match(/^\s*-\s*name:\s*(.+)\s*$/);
    if (m) {
      let name = m[1].trim();
      // 去掉包裹的引号
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
