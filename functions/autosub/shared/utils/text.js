/**
 * text utils
 * - 拆分混合文本为“可能的节点行”
 * - 兼容：多行 / 一行多个链接 / 空格逗号分号分隔
 */

export function splitMixedTextToLines(text) {
  const s = String(text || "");

  // 先统一换行
  const rows = s.replace(/\r/g, "\n").split("\n");

  const out = [];

  for (const row of rows) {
    const r = row.trim();
    if (!r) continue;

    // 允许一行里混多个链接（空格/逗号/分号/|）
    const parts = r.split(/\s+|,|;|\|/g).filter(Boolean);

    for (const p of parts) {
      const v = String(p).trim();
      if (v) out.push(v);
    }
  }

  return out;
}
