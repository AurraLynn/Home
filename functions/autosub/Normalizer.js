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

function pickString(v) {
  if (v === null || v === undefined) return "";
  const s = String(v).trim();
  return s;
}

export function normalizeNodes(nodes = []) {
  const seen = new Set();
  const out = [];

  for (const n of nodes || []) {
    if (!n || typeof n !== "object") continue;

    const type = (n.type ? String(n.type) : "unknown").toLowerCase() || "unknown";

    // ===== 生成 raw =====
    let raw = "";

    if (n.raw && pickString(n.raw)) {
      raw = pickString(n.raw);
    } else if (n.url && pickString(n.url)) {
      raw = pickString(n.url);
    } else if (n.link && pickString(n.link)) {
      raw = pickString(n.link);
    } else if (n.origin && pickString(n.origin)) {
      raw = pickString(n.origin);
    } else if (n.server && n.port) {
      raw = `${n.server}:${n.port}`;
    } else {
      try {
        raw = JSON.stringify(n);
      } catch {
        raw = "";
      }
    }

    const key = `${type}:${raw}`;
    if (seen.has(key)) continue;
    seen.add(key);

    out.push({
      ...n,
      type,
      raw,              /* 确保后续渲染/调试总能看到 raw */
      name: n.name || "",
    });
  }

  return out;
}