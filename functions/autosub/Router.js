/* Router.js
 * --------------------------------------------
 * 职责：
 *   - 根据 client = "clash" / "surge" / "v2ray"
 *     选择对应的渲染器输出
 *   - 兜底行为：输出 v2ray 样式的 base64 文本
 *
 * 调用关系：
 *   index.js 解析 UA / query → 得到 client 字符串
 *   Exit.js 调用 renderSubscription(...)
 *   renderSubscription 调用 routeAndRender(...)
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* 文本转 Base64（UTF-8 安全处理） */
function toB64(text) {
    const t = String(text || "").trim();
    if (!t) return "";
    // Workers 环境内置 btoa，这里用 encodeURIComponent 兼容中文
    return btoa(unescape(encodeURIComponent(t)));
}

/* 统一路由出口：nodes → 对应客户端格式内容 */
export function routeAndRender(
    nodes,
    {
        client = "v2ray",   /* "clash" | "surge" | "v2ray" */
        rawText = "",       /* 原始文本：用于 v2ray(Base64) 兜底 */
        // query, source 暂时用不到，但保留以便以后扩展
        query = {},
        source = "",
    } = {},
) {
    const c = String(client || "v2ray").toLowerCase();

    /* Clash 系：生成简单 Clash 配置（含 DNS / 规则 / 代理组） */
    if (c === "clash") {
        return renderClash(nodes, { client, query, source });
    }

    /* Surge：只输出 [Proxy] 节点列表 */
    if (c === "surge") {
        return renderSurge(nodes, { client, query, source });
    }

    /* 其它：默认作为 v2ray 订阅，返回 base64 文本 */
    return {
        body: toB64(rawText),
        contentType: "text/plain; charset=utf-8",
    };
}