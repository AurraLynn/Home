/**
 * /autosub 统一订阅入口（根路径）
 * - 使用 onRequest 形态（你已验证这是你项目里最稳定的写法）
 * - 保留 query
 * - client 优先 query 指定；识别不到默认 v2ray(base64)
 * - 源数据支持：
 *    1) ?text= 直接传原文
 *    2) POST body 原文
 *    3) ?id= 从站内 Paste 读取
 */

import { renderSubscription } from "./Exit.js";

function detectClient(request) {
  const url = new URL(request.url);

  // ✅ 你要求“保留 query”，所以 query 优先
  const q = (url.searchParams.get("client") || "").trim().toLowerCase();
  if (q) return q;

  // 你之前的规则：识别不到默认 v2ray(Base64)
  const ua = (request.headers.get("user-agent") || "").toLowerCase();

  if (ua.includes("stash")) return "stash";
  if (ua.includes("surge")) return "surge";
  if (ua.includes("quantumult")) return "qx";
  if (ua.includes("loon")) return "loon";
  if (ua.includes("shadowrocket")) return "shadowrocket";
  if (ua.includes("clash") || ua.includes("mihomo") || ua.includes("meta")) return "clash";
  if (ua.includes("sing-box") || ua.includes("singbox")) return "singbox";

  return "v2ray";
}

async function loadRawText(request) {
  const url = new URL(request.url);

  // 1) ?text=
  const text = url.searchParams.get("text");
  if (text && text.trim()) return text;

  // 2) POST body
  if (request.method === "POST") {
    const body = await request.text();
    if (body && body.trim()) return body;
  }

  // 3) ?id= 走你站内 Paste
  const id = url.searchParams.get("id");
  if (id && id.trim()) {
    const u = new URL(request.url);
    // 用相对路径，避免环境差异
    u.pathname = `/api/paste/${id}`;
    // 保留原 query 也没问题，但这里避免干扰 paste 接口
    u.search = "";
    const r = await fetch(u.toString(), {
      headers: { "accept": "text/plain" },
    });
    if (r.ok) {
      const t = await r.text();
      if (t && t.trim()) return t;
    }
  }

  return "";
}

export async function onRequest(context) {
  const { request } = context;
  const url = new URL(request.url);

  const client = detectClient(request);

  const rawText = await loadRawText(request);

  // 没有任何源内容时给明确提示
  if (!rawText.trim()) {
    const help = [
      "AUTOSUB: no source content",
      "",
      "Usage:",
      "  1) /autosub?text=...",
      "  2) POST /autosub  (raw text body)",
      "  3) /autosub?id=PASTE_ID",
      "",
      "Client:",
      "  /autosub?client=clash|surge|qx|stash|singbox|v2ray",
      "",
      `Current client = ${client}`,
    ].join("\n");

    return new Response(help, {
      status: 400,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  // 交给你的统一流水线
  const { body, contentType } = renderSubscription(rawText, {
    client,
    // 你如果后面想把原 query 透传给 Router/Renderers
    query: Object.fromEntries(url.searchParams.entries()),
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
