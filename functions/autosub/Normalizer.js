/*
  normalizeNodes

  - 功能：
      • 去重（按 协议类型 + 原始串 作为 key）
      • 补齐 name 字段
      • 对没有 raw 的节点，自动生成一个 raw，避免被误丢弃

  - 说明：
      之前的版本对 `!n.raw` 直接 continue，
      会导致某些解析器没有填 raw 的节点（例如 vless）被过滤掉。
      现在改为：
        • 优先使用 n.raw
        • 没有 raw 时，尝试用 url / server:port / JSON 串来生成 rawKey
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