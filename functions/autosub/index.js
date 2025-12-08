1import { detectClient } from "./shared/clientDetect.js";
import { renderSubscription } from "./Exit.js";

// ✅ 先用最小可用输入源：
// - POST body
// - ?text=...
// 后续你再替换成你真实的 KV/R2/paste 读取
async function loadRawText(request) {
    if (request.method === "POST") return await request.text();

    const url = new URL(request.url);
    const t = url.searchParams.get("text");
    if (t) return t;

    return "";
}

export default {
    async fetch(request, env, ctx) {
        const client = detectClient(request);
        const rawText = await loadRawText(request);

        const { body, contentType } = renderSubscription(rawText, { client });

        return new Response(body, {
            headers: {
                "content-type": contentType,
                "cache-control": "no-store",
            },
        });
    },
};