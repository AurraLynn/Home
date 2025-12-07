// functions/api/sub/Converter.js
//
// 支持输入：
// - body: 原始节点文本（从 KV 拿出来的内容，或前端直接 POST）
// - client: quantumultx / surge / clash / stash / base64 / 其他
//
// 支持输出：
// - Quantumult X 订阅（由 /api/sub/QuantumultX 生成）
// - Surge 订阅（由 /api/sub/Surge 生成）
// - Clash / Stash 订阅（由 /api/sub/Clash 生成）
// - Base64 订阅（整段原文按 UTF-8 → Base64 编码）
//
// client 行为：
// - client=quantumultx → 调用 /api/sub/QuantumultX
// - client=surge      → 调用 /api/sub/Surge
// - client=clash      → 调用 /api/sub/Clash
// - client=stash      → 调用 /api/sub/Clash（同 Clash）
// - 其他 / 未指定    → 直接返回 Base64（V2Ray 常规订阅）

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const bodyText = (await request.text()) ?? "";
  const origin = url.origin;

  // === 1. 需要转发到子接口的客户端 ===
  if (client === "quantumultx") {
    return proxyToSubHandler(origin + "/api/sub/QuantumultX", bodyText);
  }

  if (client === "surge") {
    return proxyToSubHandler(origin + "/api/sub/Surge", bodyText);
  }

  if (client === "clash" || client === "stash") {
    return proxyToSubHandler(origin + "/api/sub/Clash", bodyText);
  }

  // === 2. 其他一律按 Base64 订阅返回 ===
  const b64 = utf8ToBase64(bodyText || "");
  return new Response(b64 + "\n", {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// 把 body 转发给指定子接口（QuantumultX / Surge / Clash）
async function proxyToSubHandler(targetUrl, bodyText) {
  let resp;
  try {
    resp = await fetch(targetUrl, {
      method: "POST",
      body: bodyText,
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  } catch (e) {
    const msg =
      e && typeof e === "object" && "message" in e
        ? e.message
        : String(e || "unknown error");
    return new Response("convert error: " + msg, {
      status: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  const text = await resp.text();
  if (!resp.ok) {
    return new Response(text || "convert error", {
      status: resp.status,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  return new Response(text, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

// UTF-8 → Base64（用于生成通用订阅）
function utf8ToBase64(str) {
  try {
    return btoa(unescape(encodeURIComponent(str)));
  } catch (_e) {
    return "";
  }
}