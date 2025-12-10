/* Normalizer.js
 *
 * 职责：
 *   - 对 Parser 产出的 Node[] 做轻量“清洗”
 *   - 功能：
 *       • 去重：按 (type + raw) 作为 key
 *       • 补齐：type 统一小写；name 始终存在；确保 raw 存在
 *   - 目的：
 *       • 避免解析器遗漏 raw 导致节点被过滤
 *       • 给 renderer 提供稳定字段（type / raw / name / server / port）
 */

export function normalizeNodes(nodes = []) {
    const out = [];
    const seen = new Set();

    for (const n of nodes || []) {
        if (!n || (n.type == null && !n.raw)) continue;

        const type = String(n.type || n.protocol || "unknown").toLowerCase();

        let raw = n.raw;
        if (!raw) {
            if (n.url) {
                raw = String(n.url);
            } else if (n.server && n.port) {
                raw = `${n.server}:${n.port}`;
            } else {
                try {
                    raw = JSON.stringify(n);
                } catch {
                    raw = "";
                }
            }
        }
        if (!raw) continue;

        const key = `${type}:${raw}`;
        if (seen.has(key)) continue;
        seen.add(key);

        out.push({
            ...n,
            type,
            raw,
            name: n.name || "",
        });
    }

    return out;
}