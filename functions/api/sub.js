// functions/api/sub.js
// GET /api/sub?id=<pasteId>&client=<clientName>
// 1. 从 KV: Paste 读取内容
// 2. 调 /api/node-convert?client=xxx 转换
// 3. 作为订阅输出

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

  // ===== 1. 只用一个变量名：Paste =====
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

  // ===== 2. client 类型 =====
  if (!client) {
    client = detectClientFromUA(ua);
  }
  if (!client) {
    client = "v2ray"; // 识别不了就走 Base64 订阅
  }

  // ===== 3. 内部调用 node-convert =====
  const origin = url.origin;
  const convertUrl = `${origin}/api/node-convert?client=${encodeURIComponent(
    client
  )}`;

  const res = await fetch(convertUrl, {
    method: "POST",
    body: raw,
  });

  // ===== 4. 透传结果 =====
  const respHeaders = new Headers(res.headers);
  if (client === "sing-box") {
    respHeaders.set("content-type", "application/json; charset=utf-8");
  } else {
    respHeaders.set("content-type", "text/plain; charset=utf-8");
  }

  return new Response(res.body, {
    status: res.status,
    headers: respHeaders,
  });
}

// 从 KV 记录里抽取文本内容
function extractContentFromRecord(stored) {
  if (!stored) return "";

  const trimmed = stored.trim();
  const firstChar = trimmed[0];

  // 纯文本
  if (firstChar !== "{" && firstChar !== "[") {
    return stored;
  }

  // JSON：优先找 content / text / body / raw / nodeContent / data
  try {
    const obj = JSON.parse(trimmed);
    if (typeof obj.content === "string") return obj.content;
    if (typeof obj.text === "string") return obj.text;
    if (typeof obj.body === "string") return obj.body;
    if (typeof obj.raw === "string") return obj.raw;
    if (typeof obj.nodeContent === "string") return obj.nodeContent;
    if (typeof obj.data === "string") return obj.data;
    return stored;
  } catch (e) {
    return stored;
  }
}

// UA → client
function detectClientFromUA(ua) {
  const u = (ua || "").toLowerCase();

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
