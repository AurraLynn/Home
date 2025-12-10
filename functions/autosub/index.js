/* index.js
 * 入口：
 *   - Cloudflare Pages Functions 路由 /autosub
 *
 * 职责：
 *   - 读取 URL 参数、UA
 *   - 从 KV(Paste_Sub) / query / body 获取原始文本 rawText
 *   - 决定 client = clash / surge / v2ray（Base64 原文）
 *   - 调用 Exit.js 输出最终内容
 */

import { renderSubscription } from "./Exit.js";
import { pickClientFromUA } from "./Router.js";

/* 获取绑定的 KV 命名空间（Paste_Sub） */
function getPasteKV(env) {
    return env && env.Paste_Sub ? env.Paste_Sub : null;
}

/* 从 KV 里按 id 读取原始文本 */
async function loadFromKVById(env, id) {
    if (!id) return "";

    const kv = getPasteKV(env);
    if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

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

    // KV 中不是 JSON 就按 text 取
    const rawText = await kv.get(id, "text").catch(() => "");
    return rawText && String(rawText).trim() ? String(rawText) : "";
}

/* 选择 client：优先 query，其次特殊 text 调试，其次 UA，默认 v2ray(Base64) */
function pickClient(url, ua) {
    const p = (url.searchParams.get("client") || "").trim().toLowerCase();

    // 1) 显式指定 client=xxx
    if (p === "clash" || p === "surge" || p === "v2ray") {
        return p;
    }

    // 2) 未指定 client，但带有 ?text=xxx → 当成调试用，固定输出 Clash
    if (url.searchParams.has("text")) {
        return "clash";
    }

    // 3) 其它情况：根据 UA 猜测（clash/surge）；识别失败 → v2ray(Base64)
    return pickClientFromUA(ua);
}

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const ua = request.headers.get("User-Agent") || "";

        const client = pickClient(url, ua);

        let rawText = "";
        let source = "";

        // 1) 优先：从 KV 里按 id 拉取
        const id = (url.searchParams.get("id") || "").trim();
        if (id) {
            rawText = await loadFromKVById(env, id).catch(() => "");
            if (rawText) {
                source = "kv:id";
            }
        }

        // 2) 其次：query 直接带文本 ?text= / ?raw=
        if (!rawText) {
            const qText =
                url.searchParams.get("text") ||
                url.searchParams.get("raw") ||
                "";
            if (qText && String(qText).trim()) {
                rawText = String(qText);
                source = "query";
            }
        }

        // 3) 再次：POST / PUT 等 body 里直接发文本
        if (!rawText && request.method !== "GET") {
            const bodyText = await request.text().catch(() => "");
            if (bodyText && String(bodyText).trim()) {
                rawText = String(bodyText);
                source = "body";
            }
        }

        // 4) 兜底：完全没有就给个空串
        if (!rawText) {
            rawText = "";
            source = source || "empty";
        }

        const { body, contentType } = renderSubscription(rawText, {
            client,
            source,
            ua,
            query: Object.fromEntries(url.searchParams.entries()),
        });

        return new Response(body || "", {
            headers: {
                "content-type": contentType || "text/plain; charset=utf-8",
                "cache-control": "no-store",
            },
        });
    },
};