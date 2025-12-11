/* Normalizer.js
 * 文件作用：
 *   - 清洗节点数据，补全必需字段
 *   - 按 type+raw 去重
 */

export function normalizeNodes(nodes = []) {
    const out = [];
    const seen = new Set();

    for (const n of nodes) {
        if (!n) continue;

        const type = (n.type || "").toLowerCase().trim();
        const raw = (n.raw || "").trim();
        if (!type || !raw) continue;

        const key = `${type}:${raw}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const name = n.name || n.ps || n.remark || "";

        out.push({
            ...n,
            type,
            raw,
            name,
        });
    }

    return out;
}