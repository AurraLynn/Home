/**
 * /autosub 统一订阅入口（根路径）
 *
 * ✅ 你项目里已验证：onRequest 形态稳定命中
 * ✅ KV 变量名：Paste_Sub
 *
 * 输入源优先级：
 *  1) ?text= 直接传原文
 *  2) POST body 传原文
 *  3) ?id= 从 KV(Paste_Sub) 读取原文（默认 key = id）
 *
 * 客户端识别：
 *  - ?client=xxx 优先（保留 query）
 *  - UA 次之
 *  - 识别不到默认 v2ray（Base64 通用订阅）
 *
 * 你只要保证同目录存在：
 *  - Exit.js（负责串 Parser/Normalizer/Router/Renderers）
 */

// 你的统一出口（你后续的 Parser/Router/Renderers 都从这里串）
import { renderSubscription } from "./Exit.js";

/** 直接使用你确认的 KV 绑定名 */
function getPasteKV(env) {
  return env?.Paste_Sub || null;
}

/**
 * 从 KV 读取 paste 原文
 * 默认假设：key = id, value = 原文
 *
 * 如果你真实 key 规则不是纯 id：
 *  - 把 kv.get(id) 改成 kv.get(`paste:${id}`) 等
 *
 * 如果你 value 是 JSON：
 *  - 改用 kv.get(id, "json")
 */
async function loadFromKVById(env, id) {
  if (!id) return "";

  const kv = getPasteKV(env);
  if (!kv) return "";

  const text = await kv.get(id);
  return text && text.trim() ? text : "";
}

/**
 * 读取用户源文本
 * 1) ?text=
 * 2) POST body
 * 3) ?id= -> KV
 */
async function loadRawText(request, env) {
  const url = new URL(request.url);

  // 1) query text
  const qText = url.searchParams.get("text");
  if (qText && qText.trim()) return qText;

  // 2) POST body
  if (request.method === "POST") {
    const body = await request.text();
    if (body && body.trim()) return body;
  }

  // 3) id -> KV
  const id = url.searchParams.get("id");
  const fromKV = await loadFromKVById(env, id);
  if (fromKV) return fromKV;

  return "";
}

/**
 * 客户端识别：
 * - query 优先
 * - UA 其次
 * - 默认 v2ray
 */
function detectClient(request) {
  const url = new URL(request.url);

  // ✅ 保留 query：优先使用用户显式指定
  const q = (url.searchParams.get("client") || "").trim().toLowerCase();
  if (q) return q;

  const ua = (request.headers.get("user-agent") || "").toLowerCase();

  if (ua.includes("stash")) return "stash";
  if (ua.includes("surge")) return "surge";
  if (ua.includes("quantumult")) return "qx";
  if (ua.includes("loon")) return "loon";
  if (ua.includes("shadowrocket")) return "shadowrocket";
  if (ua.includes("clash") || ua.includes("mihomo") || ua.includes("meta")) return "clash";
  if (ua.includes("sing-box") || ua.includes("singbox")) return "singbox";

  // 你要求：识别不到默认返回 V2Ray(Base64)
  return "v2ray";
}

/** 简单的 help 文本 */
function buildHelp(client) {
  return [
    "AUTOSUB: no source content",
    "",
    "Usage:",
    "  1) GET  /autosub?text=RAW_TEXT",
    "  2) POST /autosub  (body = RAW_TEXT)",
    "  3) GET  /autosub?id=PASTE_ID  (read from KV: Paste_Sub)",
    "",
    "Client:",
    "  /autosub?client=clash|surge|qx|stash|singbox|v2ray",
    "",
    `Current client = ${client}`,
  ].join("\n");
}

/**
 * ✅ Pages Functions 推荐稳定入口形态
 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const client = detectClient(request);
  const rawText = await loadRawText(request, env);

  if (!rawText.trim()) {
    return new Response(buildHelp(client), {
      status: 400,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  // 交给你的统一出口
  // Exit.js 里建议实现：Parser -> Normalizer -> Router -> Renderer
  const { body, contentType } = renderSubscription(rawText, {
    client,
    // 如果你后面希望 Router/Renderer 也能看到 query
    query: Object.fromEntries(url.searchParams.entries()),
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
