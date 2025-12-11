/*
 * 文件路径：functions/autosub/Normalizer.js
 * 文件作用：
 *   - 对解析得到的节点列表进行去重与清洗
 *   - 补齐 raw / name / type 等基础字段，防止节点被误丢弃
 *   - 为各客户端渲染器提供统一、干净的 Node[] 数据
 */

/*
 * 函数：normalizeNodes
 *
 * 功能：
 *   - 去重（按 协议类型 + 原始串 作为 key）
 *   - 补齐 name 字段
 *   - 对没有 raw 的节点自动生成 raw，避免在后续流程中被丢弃
 *
 * 说明：
 *   - 旧版本对 `!n.raw` 直接 continue，
 *     会导致某些解析器没有填 raw 的节点（例如 vless）被过滤掉。
 *   - 当前逻辑：
 *       • 优先使用 n.raw
 *       • 没有 raw 时，尝试用 url / server:port / JSON 串来生成 rawKey
 */

export function normalizeNodes(nodes = []) {
    const seen = new Set();
    const out = [];

    for (const n of nodes || []) {
        if (!n) continue;

        const type = String(n.type || "unknown").toLowerCase();

        // 尝试生成一个“稳定的原始 key”
        let raw = n.raw;
        if (!raw) {
            if (n.url) {
                raw = String(n.url);
            } else if (n.server && n.port) {
                raw = `${n.server}:${n.port}`;
            } else {
                // 实在没有，就用压缩后的 JSON，当成一个“原始形态”
                try {
                    raw = JSON.stringify(n);
                } catch {
                    raw = "[[unknown-node]]";
                }
            }
        }

        const key = `${type}:${raw}`;
        if (seen.has(key)) continue;
        seen.add(key);

        out.push({
            ...n,
            type,
            raw,                // 确保后面调试能看到 raw
            name: n.name || "",
        });
    }

    return out;
}