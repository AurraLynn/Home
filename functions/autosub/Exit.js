/* Exit.js
 * 统一出口：
 *   - Parser.js：原始文本 → Node[]
 *   - Normalizer.js：去重 / 补字段
 *   - Router.js：根据 client/UA 选择 Clash / Surge / Base64
 */

import { parseAnythingToNodes } from "./Parser.js";
import { normalizeNodes } from "./Normalizer.js";
import { routeAndRender } from "./Router.js";

export function renderSubscription(
    rawText,
    { client = "v2ray", query = {}, source = "", ua = "" } = {},
) {
    const nodes = parseAnythingToNodes(rawText);
    const normalized = normalizeNodes(nodes);

    return routeAndRender(normalized, {
        client,
        query,
        source,
        rawText,
        ua,
    });
}