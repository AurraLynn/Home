/**
 * 更安全的节点行拆分
 * - 不破坏 URL query 内的分号 ;
 * - 直接用 scheme 正则提取节点
 */

const SCHEME_RE =
  /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\/[^\s]+/gi;

export function splitMixedTextToLines(text) {
  const s = String(text || "");
  const rows = s.replace(/\r/g, "\n").split("\n");

  const out = [];

  for (const row of rows) {
    const r = row.trim();
    if (!r) continue;

    const matches = r.match(SCHEME_RE);
    if (matches && matches.length) {
      for (const m of matches) {
        const v = String(m).trim();
        if (v) out.push(v);
      }
      continue;
    }

    // 没有 scheme 时，轻度拆分（不包含 ;）
    const parts = r.split(/\s+|,/g).filter(Boolean);
    for (const p of parts) {
      const v = String(p).trim();
      if (v) out.push(v);
    }
  }

  return out;
}
