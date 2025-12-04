// functions/api/sub.js
// 通用订阅入口：GET /api/sub?id=<pasteId>&client=<clientName>
//
// 1. 从 KV 中读取对应 id 的原始内容
// 2. 内部调用 /api/node-convert?client=xxx 做格式转换
// 3. 输出给各客户端作为订阅地址使用

export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const id = url.searchParams.get("id");
  let client = (url.searchParams.get("client") || "").toLowerCase();
  const ua = request.headers.get("user-agent") || "";

  if (!id) {
    return new Response("missing id", { status: 400 });
  }

  // ========= 1. 从 KV 中取出原始节点内容 =========
  // 为了稳妥，这里兼容多种变量名，你至少绑定了其中一个就行
  const kv =
    env.Paste ||      // 你截图里的绑定就是这个
    env.PasteBox ||   // 之前可能用过
    env.PASTE ||
    env.Paste_KV ||
    env.PASTE_KV;

  if (!kv) {
    return new Response(
      "KV namespace for Paste not bound (tried: Paste, PasteBox, PASTE, Paste_KV, PASTE_KV)",
      { status: 500 }
    );
  }

  const stored = await kv.get(id);
  if (!stored) {
    return new Response("not found", { status: 404 });
  }

  const raw = extractContentFromRecord(stored);
  if (!raw || !raw.trim()) {
    return new Response("empty content", { status: 404 });
  }

  // ========= 2. 决定 client 类型 =========
  if (!client) {
    client = detectClientFromUA(ua);
  }
  if (!client) {
    // 识别不了，就走 v2ray（Base64 订阅），安卓客户端普遍可用
    client = "v2ray";
  }

  // ========= 3. 内部调用 /api/node-convert =========
  const origin = url.origin;
  const convertUrl = `${origin}/api/node-convert?client=${encodeURIComponent(
    client
  )}`;

  const res = await fetch(convertUrl, {
    method: "POST",
    body: raw,
  });

  // ========= 4. 把 node-convert 的响应透传出去 =========
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

/**
 * 从 KV 读出的字符串里提取真正的节点内容：
 * 1. 如果是纯文本：直接返回
 * 2. 如果是 JSON：优先取 content / text / body / raw / nodeContent 等字段
 */
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

    // 实在找不到，就把整个 JSON 再当文本返回（让 node-convert 自己处理）
    return stored;
  } catch (e) {
    // 解析 JSON 失败，当纯文本
    return stored;
  }
}

/**
 * 根据 User-Agent 猜测客户端类型，映射为 /api/node-convert 的 client 参数
 */
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
