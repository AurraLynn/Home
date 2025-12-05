// functions/api/sub/index.js
//
// 文件用途：通用订阅入口 /api/sub
//
// 支持输入：
// -  id: 从 KV: Paste 读取对应内容，例如 /api/sub?id=cs
// -  client: 可选，当前只识别 quantumultx，其它一律按 base64 处理
//
// 行为：
// -  从 Paste KV 取出原始节点文本
// -  判断当前 client（query 优先，其次 UA 自动识别）
// -  把原始文本转发给 /api/sub/node-convert?client=xxx
// -  返回 node-convert 的纯文本结果
//
// 已支持的客户端：
// -  Quantumult X
// -  使用 Base64 订阅的客户端（Shadowrocket / v2rayNG 等）

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

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

  // ===== 决定 client 类型 =====
  if (!client) {
    client = detectClientFromUA(ua);
  }

  // 现在只区分：Quantumult X / Base64
  if (client !== "quantumultx") {
    client = "base64";
  }

  // ===== 转发给 /api/sub/node-convert =====
  const origin = url.origin;
  const convertUrl = `${origin}/api/sub/node-convert?client=${encodeURIComponent(
    client
  )}`;

  const res = await fetch(convertUrl, {
    method: "POST",
    body: raw,
  });

  const outText = await res.text();

  if (!res.ok) {
    return new Response(outText || "convert error", {
      status: res.status,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  return new Response(outText, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// ===== 从 KV 记录里抽取正文内容 =====
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

    // 实在找不到，就原样返回 JSON
    return stored;
  } catch (_e) {
    return stored;
  }
}

// ===== UA → client 名 =====

function safeDecodeURIComponent(s) {
  try {
    return decodeURIComponent(s);
  } catch (_e) {
    return s || "";
  }
}

// 只识别 Quantumult X，其它一律返回空
function detectClientFromUA(ua) {
  const raw = ua || "";
  const lower = raw.toLowerCase();
  const decodedLower = safeDecodeURIComponent(raw).toLowerCase();

  const h = `${lower} ${decodedLower}`;

  if (
    h.includes("quantumult%20x") ||
    h.includes("quantumult x") ||
    h.includes("quantumultx") ||
    h.includes("quanx")
  ) {
    return "quantumultx";
  }

  // 未识别：交给上层当 base64
  return "";
}