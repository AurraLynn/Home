/* Exit.js
 * 文件作用：
 *   - 解析原始内容 → 规范化节点 → 调用 Router.js 渲染订阅
 */

import { parseAnythingToNodes } from "./Parser.js";
import { normalizeNodes } from "./Normalizer.js";
import { routeAndRender } from "./Router.js";

/* renderSubscription：对外唯一出口 */
export function renderSubscription(rawText, { client, source, ua, query } = {}) {
    const text = String(rawText || "");

    /* 第一步：把原始文本解析成节点数组 */
    const nodes = parseAnythingToNodes(text);

    /* 第二步：节点去重、补全字段 */
    const normalized = normalizeNodes(nodes);

    /* 第三步：根据 client 类型渲染为对应订阅格式 */
    return routeAndRender(normalized, {
        client,
        rawText: text,
        query,
        source,
        ua,
    });
}