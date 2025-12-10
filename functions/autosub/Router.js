/* Router.js
 * 职责：
 *   - 只在这里决定输出格式：Clash / Surge / Base64(v2ray)
 *   - 通过 client 参数 + UA 自动识别
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* 文本 → Base64（用于 v2ray 默认输出） */
function toB64(text) {
    const t = String(text || "");
    if (!t) return "";
    // Cloudflare Workers 环境下有 btoa
    return btoa(unescape(encodeURIComponent(t)));
}

/* UA 推断客户端类型：只关心 Clash 系 / Surge，其它给 v2ray(Base64) */
export function pickClientFromUA(uaRaw = "") {
    const ua = String(uaRaw || "").toLowerCase();

    if (!ua) return "v2ray";

    if (ua.includes("surge")) return "surge";

    // Clash / Mihomo / Meta / Stash 等都使用 Clash YAML
    if (
        ua.includes("clash") ||
        ua.includes("mihomo") ||
        ua.includes("meta") ||
        ua.includes("stash") /* 只输出节点 不包含配置 */
    ) {
        return "clash";
    }

    // 无法识别时 → v2ray(Base64)
    return "v2ray";
}

/* 根据 client + UA 路由到对应 renderer */
export function routeAndRender(
    nodes,
    { client = "v2ray", rawText = "", ua = "", query = {}, source = "" } = {},
) {
    let c = String(client || "v2ray").toLowerCase();
    if (c !== "clash" && c !== "surge" && c !== "v2ray") {
        c = pickClientFromUA(ua);
    }

    if (c === "clash") {
        return renderClash(nodes || [], { query, source, ua });
    }

    if (c === "surge") {
        return renderSurge(nodes || [], { query, source, ua });
    }

    // 默认：v2ray Base64（原始未解析文本）
    return {
        body: toB64(rawText),
        contentType: "text/plain; charset=utf-8",
    };
}