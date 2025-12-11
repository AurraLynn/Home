/*
 * 文件路径：functions/autosub/index.js
 * 文件作用：
 *   - 作为 /autosub 路由入口接收订阅转换请求
 *   - 从 query、POST body 或 KV(Paste_Sub) 获取原始订阅内容
 *   - 调用 Exit.js 进行解析、归一化并生成最终订阅输出
 */

import { renderSubscription } from "./Exit.js";

/*
 * 工具函数：从 env 中获取绑定的 Paste_Sub KV 空间
 *   - env.Paste_Sub 未绑定时后面会抛出错误提醒
 */
function getPasteKV(env) {
    return env?.Paste_Sub || null;
}

/*
 * 工具函数：根据 id 从 Paste_Sub KV 中读取一条原始内容
 *   - 优先按 JSON 读取，尝试从 content/text/data/raw/value 字段取文本
 *   - 如果不是 JSON，则当作纯文本或 JSON 字符串兜底解析
 */
async function loadFromKVById(env, id) {
    if (!id) return "";

    const kv = getPasteKV(env);
    if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

    const rec = await kv.get(id, "json").catch(() => null);
    if (rec && typeof rec === "object") {
        const raw = rec.content || rec.text || rec.data || rec.raw || rec.value || "";
        return raw && String(raw).trim() ? String(raw) : "";
    }

    const stored = await kv.get(id);
    if (!stored) return "";
    const s = String(stored).trim();
    if (!s) return "";

    try {
        const obj = JSON.parse(s);
        const raw = obj?.content || obj?.text || obj?.data || obj?.raw || obj?.value || "";
        if (raw && String(raw).trim()) return String(raw);
    } catch {}

    return s;
}

/*
 * 工具函数：从请求中抽取“原始订阅文本”及来源说明
 *   - 优先使用 ?text=...（方便快速测试）
 *   - 其次使用 POST body
 *   - 再次使用 ?id=... 从 KV 中读取
 *   - 都没有则返回空字符串和 source=none
 */
async function loadRawPack(request, env) {
    const url = new URL(request.url);

    const qText = url.searchParams.get("text");
    if (qText && qText.trim()) return { rawText: qText, source: "query:text" };

    if (request.method === "POST") {
        const body = await request.text();
        if (body && body.trim()) return { rawText: body, source: "post:body" };
    }

    const id = (url.searchParams.get("id") || "").trim();
    if (id) {
        const t = await loadFromKVById(env, id);
        return { rawText: t || "", source: t ? "kv:record.content" : "kv:miss" };
    }

    return { rawText: "", source: "none" };
}

/*
 * 工具函数：识别客户端类型 client
 *   - 优先使用 ?client=... 参数
 *   - 否则根据 UA 自动判断常见客户端（Stash / Surge / QX / Clash / Sing-box 等）
 *   - 找不到时默认返回 v2ray
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

/*
 * 工具函数：当没有任何可用内容时返回一段纯文本帮助说明
 *   - 包含基本使用方法和当前识别的 client/source 信息
 */
function buildHelp(client, source) {
    return [
        "AUTOSUB: no source content",
        "",
        "Usage:",
        "  1) GET  /autosub?text=RAW_TEXT",
        "  2) POST /autosub  (body = RAW_TEXT)",
        "  3) GET  /autosub?id=PASTE_ID  (KV: Paste_Sub -> record.content)",
        "",
        "Client:",
        "  /autosub?client=clash|surge|qx|v2ray",
        "",
        `Current client = ${client}`,
        `Source = ${source}`,
    ].join("\n");
}

/*
 * 入口函数：Cloudflare Pages Functions / Workers 的 onRequest
 *   - 解析 debug/client 等参数
 *   - 调用 loadRawPack 获取原始文本和来源
 *   - debug=1 时返回调试 JSON，方便检查 KV 绑定与内容长度
 *   - 无内容时返回帮助说明，有内容时调用 renderSubscription 返回转换结果
 */
export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    const debug = url.searchParams.get("debug") === "1";
    const client = detectClient(request);

    let rawPack;
    try {
        rawPack = await loadRawPack(request, env);
    } catch (e) {
        if (debug) {
            return new Response(JSON.stringify({
                ok: false,
                error: String(e?.message || e),
                hasPasteSubBinding: !!env?.Paste_Sub,
                client,
            }, null, 2), {
                status: 500,
                headers: { "content-type": "application/json; charset=utf-8" },
            });
        }
        return new Response(String(e?.message || e), { status: 500 });
    }

    const { rawText, source } = rawPack;

    if (debug) {
        return new Response(JSON.stringify({
            ok: true,
            debug: true,
            route: "/autosub",
            id: url.searchParams.get("id") || null,
            client,
            source,
            hasPasteSubBinding: !!env?.Paste_Sub,
            rawLength: rawText ? String(rawText).length : 0,
        }, null, 2), {
            headers: {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-store",
            },
        });
    }

    if (!rawText || !rawText.trim()) {
        return new Response(buildHelp(client, source), {
            status: 400,
            headers: { "content-type": "text/plain; charset=utf-8" },
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