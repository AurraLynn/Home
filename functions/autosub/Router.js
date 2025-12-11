/* Router.js
 * 文件作用：
 *   - 根据 UA 判断使用哪个客户端类型（clash / surge / v2ray）
 *   - 根据客户端类型选择对应的渲染方式（Clash / Surge / v2ray Base64）
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* UA → "clash" / "surge" / "v2ray"（不对 Stash 做任何判断） */
export function pickClientFromUA(uaRaw) {
    const ua = (uaRaw || "").toLowerCase();

    if (!ua) return "v2ray";

    if (ua.includes("surge")) return "surge";

    if (
        ua.includes("clash") ||
        ua.includes("mihomo") ||
        ua.includes("meta") ||
        ua.includes("cfw") ||
        ua.includes("clash for windows")
    ) {
        return "clash";
    }

    return "v2ray";
}

/* 判断文本里是否包含任意一种节点协议前缀 */
function containsNodeProtocol(str) {
    if (!str) return false;
    const t = String(str).toLowerCase();
    return (
        t.includes("ss://") ||
        t.includes("vmess://") ||
        t.includes("vless://") ||
        t.includes("trojan://") ||
        t.includes("hysteria2://") ||
        t.includes("hy2://") ||
        t.includes("hysteria://")
    );
}

/* 安全地尝试 Base64 解码（仅用于检测，不做真实业务逻辑） */
function safeAtobDetect(b64) {
    if (!b64) return "";
    const s = String(b64).trim();
    try {
        return decodeURIComponent(escape(atob(s)));
    } catch {
        try {
            return atob(s);
        } catch {
            return "";
        }
    }
}

/* 判断原文是否“看起来像订阅 Base64 串” */
function looksLikeBase64Subscription(raw) {
    const text = String(raw || "").trim();
    if (!text) return false;

    if (containsNodeProtocol(text)) return false;

    const compact = text.replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/=]+$/.test(compact)) return false;

    const decoded = safeAtobDetect(compact);
    if (!decoded) return false;

    return containsNodeProtocol(decoded);
}

/* 把明文文本编码成 Base64（兼容中文） */
function toB64(text) {
    const t = String(text || "").trim();
    if (!t) return "";
    return btoa(unescape(encodeURIComponent(t)));
}

/* 主路由：根据 client 决定走哪种渲染方式 */
export function routeAndRender(
    nodes,
    {
        client = "v2ray",
        rawText = "",
        query = {},
        source = "",
        ua = "",
    } = {},
) {
    const c = String(client || "v2ray").toLowerCase();

    /* client=clash：调用 Clash 渲染器，生成完整 YAML 配置 */
    if (c === "clash") {
        return renderClash(nodes, { client, query, source, rawText, ua });
    }

    /* client=surge：调用 Surge 渲染器，只生成 [Proxy] 节 */
    if (c === "surge") {
        return renderSurge(nodes, { client, query, source, rawText, ua });
    }

    /* 其它情况（v2ray / 未知）：作为 Base64 订阅输出 */
    const original = String(rawText || "");
    let out = "";

    if (looksLikeBase64Subscription(original)) {
        out = original.trim();
    } else {
        out = toB64(original);
    }

    return {
        body: out,
        contentType: "text/plain; charset=utf-8",
    };
}