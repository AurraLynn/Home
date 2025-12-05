// functions/api/sub/Converter.js
//
// 文件用途：通用格式转换路由（内部使用）
//
// 支持输入：
// -  body: 原始节点文本（从 KV 拿出来的内容，或前端直接 POST）
// -  client: quantumultx / base64（其它值也当 base64 处理）
//
// 支持输出：
// -  Quantumult X 订阅行（由 /api/sub/QuantumultX 生成）
// -  Base64 订阅（整段原文按 UTF-8 → Base64 编码）
//
// client 行为：
// -  client=quantumultx：转给 /api/sub/QuantumultX 处理
// -  其它或空：整段原文做 Base64 返回
//
// 已支持的客户端：
// -  Quantumult X
// -  使用 Base64 订阅的客户端

export async function onRequestPost(context) {
    const { request } = context;
    const url = new URL(request.url);
    const origin = url.origin;

    let client = (url.searchParams.get("client") || "base64").toLowerCase();
    const rawText = await request.text();
    const bodyText = rawText || "";

    // ===== Quantumult X：转发到 /api/sub/QuantumultX =====
    if (client === "quantumultx") {
        const qxUrl = `${origin}/api/sub/QuantumultX`;
        const res = await fetch(qxUrl, {
            method: "POST",
            body: bodyText,
        });

        const text = await res.text();
        return new Response(text, {
            status: res.status,
            headers: { "content-type": "text/plain; charset=utf-8" },
        });
    }

    // ===== Base64：整段原文做成订阅内容 =====
    const b64 = utf8ToBase64(bodyText.trim());

    return new Response(b64, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
    });
}

// UTF-8 → Base64（用于生成订阅内容）
function utf8ToBase64(str) {
    try {
        return btoa(unescape(encodeURIComponent(str)));
    } catch (_e) {
        return "";
    }
}