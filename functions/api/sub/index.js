// functions/api/sub/index.js
//
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 支持输入：
// -  URL格式
// -  URL/Base64 混合格式
// -  Base64
//
// 支持输出：
// -  Quantumult X（内部转发到 /api/sub/qx）
// -  Base64（其它 / 未识别客户端）
//
// client 行为：
// -  client=quantumultx → 调用 /api/sub/qx 做节点转换
// -  UA 识别为 Quantumult X → 调用 /api/sub/qx
// -  其它 / 未识别 → 直接返回 Base64
//
// 已支持的客户端：
// -  Quantumult X
// -  使用Base64订阅的客户端

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
    // 识别不了：默认走 Base64 订阅
    client = "v2ray";
  }

  // ===== 3A. Quantumult X → 调用 /api/sub/qx =====
  if (client === "quantumultx") {
    const origin = url.origin;
    const convertUrl = `${origin}/api/sub/qx`;

    const res = await fetch(convertUrl, {
      method: "POST",
      body: raw,
    });

    const convertedText = await res.text();

    if (!res.ok) {
      return new Response(convertedText || "convert error", {
        status: res.status,
      });
    }

    return new Response(convertedText, {
      status: 200,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  }

  // ===== 3B. 其它客户端：直接返回 Base64 订阅 =====
  const b64 = utf8ToBase64(raw.trim());
  return new Response(b64, {
    status: 200,
    headers: {
      "content-type": "text/plain; charset=utf-8",
    },
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
function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();

  // Quantumult X
  if (u.includes("quantumult x") || u.includes("quantumult_x") || u.includes("qx")) {
    return "quantumultx";
  }

  // 其它一律不识别，走 Base64
  return "";
}

// ===== 工具：UTF-8 文本 → Base64 =====
function utf8ToBase64(str) {
  return btoa(unescape(encodeURIComponent(str)));
}