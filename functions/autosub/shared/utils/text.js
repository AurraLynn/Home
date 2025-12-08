/**
 * 更安全的节点行拆分
 *
 * 目标：
 * - 不破坏 URL query 内的分号 ; 等字符
 * - 支持“混合文本里提取多个节点”
 *
 * 策略：
 * 1) 先按换行拆
 * 2) 如果一行里出现 1 个或多个 "://"
 *    用正则直接提取协议链接（不再用 ; | 之类分隔）
 * 3) 否则退回用空格/逗号做轻度拆分
 */

const SCHEME_RE = /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\/[^\s]+/gi;

export function splitMixedTextToLines(text) {
  const s = String(text || "");
  const rows = s.replace(/\r/g, "\n").split("\n");

  const out = [];

  for (const row of rows) {
    const r = row.trim();
    if (!r) continue;

    // ✅ 这一步最关键：用 scheme 正则提取
    const matches = r.match(SCHEME_RE);
    if (matches && matches.length) {
      for (const m of matches) {
        const v = String(m).trim();
        if (v) out.push(v);
      }
      continue;
    }

    // 退化策略：只用空格/逗号
    const parts = r.split(/\s+|,/g).filter(Boolean);
    for (const p of parts) {
      const v = String(p).trim();
      if (v) out.push(v);
    }
  }

  return out;
}
