/**
 * /autosub 统一订阅入口（根路径）
 *
 * ✅ 你已验证：本项目必须使用 onRequest 形态才能稳定命中
 * ✅ KV 绑定变量名：Paste_Sub
 * ✅ 你的 KV value 结构为 record(JSON)，真实文本在 record.content
 *
 * 输入源优先级：
 *  1) ?text= 直接传原文
 *  2) POST body 传原文
 *  3) ?id= 从 KV(Paste_Sub) 读取 record.content
 *
 * 客户端识别：
 *  - ?client=xxx 优先（保留 query）
 *  - UA 次之
 *  - 识别不到默认 v2ray（Base64 通用订阅）
 *
 * 依赖：
 *  - 同目录 Exit.js 必须导出 renderSubscription(rawText, options)
 */

import { renderSubscription } from "./Exit.js";

/** 直接使用你确认的 KV 绑定名 */
function getPasteKV(env) {
  return env?.Paste_Sub || null;
}

/**
 * 从 KV 读取 record，并抽取 content
 * 兼容：
 *  - 你现在的 record 结构：{ slug, content, ttlKey, ... }
 *  - 未来可能的字段别名：text/data/raw/value
 *  - 极端情况下 value 可能是纯文本
 */
async function loadFromKVById(env, id) {
  if (!id) return "";

  const kv = getPasteKV(env);
  if (!kv) {
    // 让错误更直观，方便你排查绑定
    throw new Error("KV namespace `Paste_Sub` not bound");
  }

  // ✅ 最推荐：直接 json 读取
  const rec = await kv.get(id, "json").catch(() => null);

  if (rec && typeof rec === "object") {
    const raw =
      rec.content ||
      rec.text ||
      rec.data ||
      rec.raw ||
      rec.value ||
      "";

    return raw && String(raw).trim() ? String(raw) : "";
  }

  // ✅ 兜底：如果这条数据不是 JSON 或者你有旧数据
  const stored = await kv.get(id);
  if (!stored) return "";

  const s = String(stored).trim();
  if (!s) return "";

  // 尝试把字符串当 JSON 解析
  if ((s.startsWith("{") && s.endsWith("}")) || (s.startsWith("[") && s.endsWith("]"))) {
    try {
      const obj = JSON.parse(s);
      const raw =
        obj?.content ||
        obj?.text ||
        obj?.data ||
        obj?.raw ||
        obj?.value ||
        "";
      if (raw && String(raw).trim()) return String(raw);
    } catch {}
  }

  // 否则就当纯文本
  return s;
}

/**
 * 读取用户源文本
 * 1) ?text=
 * 2) POST body
 * 3) ?id= -> KV record.content
 */
async function loadRawText(request, env) {
  const url = new URL(request.url);

  // 1) query text
  const qText = url.searchParams.get("text");
  if (qText && qText.trim()) {
    return { rawText: qText, source: "query:text" };
  }

  // 2) POST body
  if (request.method === "POST") {
    const body = await request.text();
    if (body && body.trim()) {
      return { rawText: body, source: "post:body" };
    }
  }

  // 3) id -> KV
  const id = url.searchParams.get("id");
  if (id && id.trim()) {
    const fromKV = await loadFromKVById(env, id.trim());
    if (fromKV) {
      return { rawText: fromKV, source: "kv:record.content" };
    }
    return { rawText: "", source: "kv:miss" };
  }

  return { rawText: "", source: "none" };
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

/** help 文本 */
function buildHelp(client, source, extra = "") {
  return [
    "AUTOSUB: no source content",
    "",
    "Usage:",
    "  1) GET  /autosub?text=RAW_TEXT",
    "  2) POST /autosub  (body = RAW_TEXT)",
    "  3) GET  /autosub?id=PASTE_ID  (read from KV: Paste_Sub, record.content)",
    "",
    "Client:",
    "  /autosub?client=clash|surge|qx|stash|singbox|v2ray",
    "",
    `Current client = ${client}`,
    `Source = ${source}`,
    extra ? extra : null,
  ].filter(Boolean).join("\n");
}

/**
 * ✅ Pages Functions 稳定入口
 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const client = detectClient(request);
  const debug = url.searchParams.get("debug") === "1";

  let rawPack;
  try {
    rawPack = await loadRawText(request, env);
  } catch (e) {
    // KV 未绑定等问题
    return new Response(
      buildHelp(client, "error", debug ? String(e?.message || e) : ""),
      {
        status: 500,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      }
    );
  }

  const { rawText, source } = rawPack;

  if (!rawText.trim()) {
    const kvExists = !!env?.Paste_Sub;
    const extra = debug
      ? `DEBUG: Paste_Sub bound = ${kvExists}`
      : "";

    return new Response(buildHelp(client, source, extra), {
      status: 400,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  // 交给你的统一出口
  const { body, contentType } = renderSubscription(rawText, {
    client,
    source,
    // 需要时可让 Router/Renderers 看见所有 query
    query: Object.fromEntries(url.searchParams.entries()),
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
