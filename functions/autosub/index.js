/**
 * /autosub 统一订阅入口（根路径）
 *
 * ✅ 你项目里已验证：onRequest 形态稳定命中
 * ✅ KV 绑定变量名：Paste_Sub
 * ✅ KV value 为 record(JSON)，真实节点文本在 record.content
 *
 * 输入源优先级：
 *  1) ?text=
 *  2) POST body
 *  3) ?id= -> KV(Paste_Sub) 读取 record.content
 *
 * 客户端识别：
 *  - ?client=xxx 优先（保留 query）
 *  - UA 次之
 *  - 识别不到默认 v2ray（Base64 通用订阅）
 *
 * Debug：
 *  - ?debug=1 返回调试 JSON（不输出订阅正文）
 */

import { renderSubscription } from "./Exit.js";

function getPasteKV(env) {
  return env?.Paste_Sub || null;
}

/**
 * 从 KV 读取 record 并抽取 content
 * 兼容：content/text/data/raw/value
 * 兼容：旧数据可能是纯文本
 */
async function loadFromKVById(env, id) {
  if (!id) return { raw: "", hit: false };

  const kv = getPasteKV(env);
  if (!kv) {
    throw new Error("KV namespace `Paste_Sub` not bound");
  }

  // ✅ 首选：json 读取
  const rec = await kv.get(id, "json").catch(() => null);

  if (rec && typeof rec === "object") {
    const raw =
      rec.content ||
      rec.text ||
      rec.data ||
      rec.raw ||
      rec.value ||
      "";

    const out = raw && String(raw).trim() ? String(raw) : "";
    return { raw: out, hit: !!out };
  }

  // ✅ 兜底：字符串读取
  const stored = await kv.get(id);
  if (!stored) return { raw: "", hit: false };

  const s = String(stored).trim();
  if (!s) return { raw: "", hit: false };

  // 尝试 JSON parse
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
      const out = raw && String(raw).trim() ? String(raw) : "";
      return { raw: out || s, hit: !!(out || s) };
    } catch {
      // 不是 JSON 就当纯文本
    }
  }

  return { raw: s, hit: true };
}

/**
 * 读取源文本
 */
async function loadRawPack(request, env) {
  const url = new URL(request.url);

  // 1) ?text=
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

  // 3) ?id= -> KV
  const id = (url.searchParams.get("id") || "").trim();
  if (id) {
    const { raw, hit } = await loadFromKVById(env, id);
    return {
      rawText: raw || "",
      source: hit ? "kv:record.content" : "kv:miss",
    };
  }

  return { rawText: "", source: "none" };
}

/**
 * client 识别（保留 query）
 */
function detectClient(request) {
  const url = new URL(request.url);

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

  return "v2ray";
}

function buildHelp(client, source) {
  return [
    "AUTOSUB: no source content",
    "",
    "Usage:",
    "  1) GET  /autosub?text=RAW_TEXT",
    "  2) POST /autosub  (body = RAW_TEXT)",
    "  3) GET  /autosub?id=PASTE_ID  (read KV: Paste_Sub, record.content)",
    "",
    "Client:",
    "  /autosub?client=clash|surge|qx|stash|singbox|v2ray",
    "",
    `Current client = ${client}`,
    `Source = ${source}`,
  ].join("\n");
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const debug = url.searchParams.get("debug") === "1";
  const client = detectClient(request);

  let rawPack;
  try {
    rawPack = await loadRawPack(request, env);
  } catch (e) {
    // KV 未绑定等
    if (debug) {
      return new Response(
        JSON.stringify(
          {
            ok: false,
            error: String(e?.message || e),
            hasPasteSubBinding: !!env?.Paste_Sub,
            client,
          },
          null,
          2
        ),
        {
          status: 500,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store",
          },
        }
      );
    }

    return new Response(String(e?.message || e), {
      status: 500,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  const { rawText, source } = rawPack;

  // ✅ Debug 模式：只返回调试 JSON
  if (debug) {
    const id = url.searchParams.get("id") || null;
    return new Response(
      JSON.stringify(
        {
          ok: true,
          debug: true,
          route: "/autosub",
          id,
          client,
          source,
          hasPasteSubBinding: !!env?.Paste_Sub,
          rawLength: rawText ? String(rawText).length : 0,
          // ⚠️ 不直接回显 raw 内容，避免泄露
        },
        null,
        2
      ),
      {
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
        },
      }
    );
  }

  if (!rawText || !rawText.trim()) {
    return new Response(buildHelp(client, source), {
      status: 400,
      headers: {
        "content-type": "text/plain; charset=utf-8",
        "cache-control": "no-store",
      },
    });
  }

  const { body, contentType } = renderSubscription(rawText, {
    client,
    source,
    query: Object.fromEntries(url.searchParams.entries()),
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}
