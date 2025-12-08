export function splitMixedTextToLines(text) {
  // 先按常规换行拆
  const basic = String(text || "")
    .replace(/\r/g, "\n")
    .split("\n")
    .map(s => s.trim())
    .filter(Boolean);

  // 允许一行里混多个链接（用空格/逗号/; 分隔）
  const out = [];
  for (const row of basic) {
    const parts = row.split(/\s+|,|;|\|/g).filter(Boolean);
    for (const p of parts) out.push(p);
  }
  return out;
}
