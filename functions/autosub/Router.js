/*
 * 文件路径：functions/autosub/Router.js
 * 文件作用：
 *   - 根据目标客户端 client 选择对应的渲染器
 *   - 将标准 Node[] 分发到 Clash / Surge / QX 等具体 renderer
 *   - 未匹配到已知客户端时，回退为通用 v2ray base64 订阅输出
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";
import { renderQX } from "./renderers/qx.js";

/*
 * 工具函数：将文本编码为 base64（UTF-8 安全）
 *   - 用于默认 v2ray 通用订阅输出
 */
function toB64(text) {
    const t = String(text || "").trim();
    return btoa(unescape(encodeURIComponent(t)));
}

/*
 * 函数：routeAndRender
 *
 * 功能：
 *   - 根据 client 路由到不同渲染器生成最终订阅内容
 *   - 支持：
 *       • clash → renderClash
 *       • surge → renderSurge
 *       • qx    → renderQX
 *   - 其它 / 未匹配时：
 *       • 将原始 rawText 做一次 base64 编码，作为 v2ray 通用订阅返回
 *
 * 入参：
 *   - nodes：normalize 后的节点列表 Node[]
 *   - client：目标客户端类型，字符串（默认 "v2ray"）
 *   - rawText：未解析的原始订阅文本，用于兜底 base64 输出
 *
 * 返回：
 *   - { body, contentType }：供 index.js 直接作为 HTTP 响应返回
 */
export function routeAndRender(nodes, { client = "v2ray", rawText = "" } = {}) {
    const c = String(client || "v2ray").toLowerCase();

    if (c === "clash") return renderClash(nodes);
    if (c === "surge") return renderSurge(nodes);
    if (c === "qx") return renderQX(nodes);

    // 识别不到已知客户端时，默认走 v2ray base64 订阅格式
    return {
        body: toB64(rawText),
        contentType: "text/plain; charset=utf-8",
    };
}