// functions/api/sub/Converter.js
//
// 支持输入：
// - body: 原始节点文本（从 KV 拿出来的内容，或前端直接 POST）
// - client: quantumultx / surge / clash / stash / base64 / 其他
//
// 支持输出：
// - Quantumult X 订阅（由 /api/sub/QuantumultX 生成）
// - Surge 订阅（由 /api/sub/Surge 生成）
// - Clash 订阅（由 /api/sub/Clash 生成，通常为完整配置前的 proxies 段）
// - Stash 订阅（由 /api/sub/Stash 生成，只返回 proxies 段）
// - Base64 订阅：
//      - 如果 body 已经是 V2Ray 风格 Base64 订阅（解码后能看到 vmess:// 等），直接原样返回
//      - 否则将 body 视为纯文本，按 UTF-8 → Base64 编码一次
//
// client 行为：
// - client=quantumultx → 调用 /api/sub/QuantumultX
// - client=surge      → 调用 /api/sub/Surge
// - client=clash      → 调用 /api/sub/Clash
// - client=stash      → 调用 /api/sub/Stash
// - 其他 / 未指定    → 走 Base64 订阅逻辑（上面两点）

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

  if (client === "clash") {
    return proxyToSubHandler(origin + "/api/sub/Clash", bodyText);
  }

  if (client === "stash") {
    return proxyToSubHandler(origin + "/api/sub/Stash", bodyText);
  }

  // === 2. 其它一律按 Base64 订阅返回，但要避免二次 Base64 ===
  const headers = { "content-type": "text/plain; charset=utf-8" };

  // 2.1 如果 body 看起来已经是 V2Ray 风格 Base64 订阅（解出来有 vmess:// 等），直接原样返回
  if (isProbablyV2rayBase64(bodyText)) {
    const out = (bodyText || "").trim() + "\n";
    return new Response(out, {
      status: 200,
      headers,
    });
  }

  // 2.2 否则，按纯文本做一次 UTF-8 → Base64（常规订阅）
  const b64 = utf8ToBase64(bodyText || "");
  return new Response(b64 + "\n", {
    status: 200,
    headers,
  });
}

// 把 body 转发给指定子接口（QuantumultX / Surge / Clash / Stash）
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

// 判断 body 很可能已经是 V2Ray 风格 Base64 订阅：
// - 本身不包含 "://"
// - 去掉空白后全是 Base64 字符
// - 解码后包含 vmess:// / vless:// / ss:// / trojan:// / hysteria2:// / hy2:// 等
function isProbablyV2rayBase64(str) {
  if (!str) return false;
  const raw = str.trim();
  if (!raw) return false;

  // 已经是明文订阅（行里有 vmess:// 等），那不是 Base64
  if (
    raw.includes("://") ||
    raw.includes("vmess://") ||
    raw.includes("vless://") ||
    raw.includes("ss://") ||
    raw.includes("trojan://") ||
    raw.includes("hysteria2://") ||
    raw.includes("hy2://")
  ) {
    return false;
  }

  // 去掉所有空白，看是不是纯 Base64 字符
  const compact = raw.replace(/\s+/g, "");
  if (!/^[A-Za-z0-9+/=]+$/.test(compact)) return false;
  if (compact.length < 16) return false; // 太短的基本不是订阅

  // 做一次 Base64 解码，看看里面有没有节点前缀
  try {
    const bin = atob(compact.replace(/-/g, "+").replace(/_/g, "/"));
    if (
      bin.includes("vmess://") ||
      bin.includes("vless://") ||
      bin.includes("ss://") ||
      bin.includes("trojan://") ||
      bin.includes("hysteria2://") ||
      bin.includes("hy2://")
    ) {
      return true;
    }
  } catch (_e) {
    return false;
  }

  return false;
}
