/* index.js
 * 文件作用：
 *   - 作为 Cloudflare Pages Functions 入口
 *   - 获取节点文本 → 判断客户端类型 → 调用 Exit.js 生成订阅内容
 *   - 通过 Router.js 里的 pickClientFromUA 按 UA 自动识别客户端类型
 */

/* 引入出口渲染函数：把节点渲染成订阅 */
import { renderSubscription } from "./Exit.js";
/* 引入 UA 识别函数：根据 UA 推断 clash / surge / v2ray */
import { pickClientFromUA } from "./Router.js";

/* 从 env 中拿到 Paste_Sub 这个 KV 命名空间 */
function getPasteKV(env) {
    return env && env.Paste_Sub ? env.Paste_Sub : null;
}

/* 按 id 从 KV 中读取原始内容（兼容 JSON + 纯文本两种存储） */
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
        if (raw && String(raw).trim()) return String(raw);
    }

    const rawText = await kv.get(id, "text").catch(() => "");
    if (rawText && String(rawText).trim()) return String(rawText);

    return "";
}

/* 决定最终 client：优先 query 里的 ?client= ，然后 ?text= ，最后按 UA 判断 */
function decideClient(url, uaRaw) {
    const p = (url.searchParams.get("client") || "")
        .trim()
        .toLowerCase();

    // 显式指定优先
    if (p === "clash" || p === "surge" || p === "v2ray") return p;

    // 有 ?text= 时默认当 clash，用于浏览器调试
    if (url.searchParams.has("text")) return "clash";

    // 其余情况走 UA 自动识别
    return pickClientFromUA(uaRaw);
}

/* Cloudflare Pages Functions 入口：处理 /autosub 请求 */
export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);
    const path = url.pathname;

    /* 限定路径：这里只接管 /autosub，其它路径交给静态页面 */
    if (path !== "/autosub") {
        return new Response("Not Found", { status: 404 });
    }

    /* 取 UA，用于后面判断客户端类型 */
    const ua = request.headers.get("User-Agent") || "";

    /* 处理 CORS 预检请求 */
    if (request.method === "OPTIONS") {
        return new Response(null, {
            status: 204,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type",
                "Access-Control-Allow-Credentials": "true",
            },
        });
    }

    /* 确定目标客户端类型：clash / surge / v2ray */
    const client = decideClient(url, ua);

    /* rawText 保存最终要解析的原始文本，source 记录来源 */
    let rawText = "";
    let source = "";

    /* 来源 1：?id=xxx，从 KV 读取 */
    const id = (url.searchParams.get("id") || "").trim();
    if (id) {
        rawText = await loadFromKVById(env, id).catch(() => "");
        if (rawText) source = "kv:id";
    }

    /* 来源 2：query 上的 ?text= 或 ?raw= */
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

    /* 来源 3：请求 body（POST/PUT 等） */
    if (!rawText && request.method !== "GET") {
        const bodyText = await request.text().catch(() => "");
        if (bodyText && String(bodyText).trim()) {
            rawText = String(bodyText);
            source = "body";
        }
    }

    /* 来源 4：都没有时，兜底为空文本 */
    if (!rawText) {
        rawText = "";
        if (!source) source = "empty";
    }

    /* 把 URL 上所有 query 参数拍平为对象，传给后续逻辑 */
    const queryObj = Object.fromEntries(url.searchParams.entries());

    /* 调用 Exit.js：解析节点 → 规范化 → 按 client 渲染订阅内容 */
    const { body, contentType } = renderSubscription(rawText, {
        client,
        source,
        ua,
        query: queryObj,
    });

    /* 返回订阅内容响应 */
    return new Response(body || "", {
        headers: {
            "content-type": contentType || "text/plain; charset=utf-8",
            "cache-control": "no-store",
            "Access-Control-Allow-Origin": "*",
        },
    });
}