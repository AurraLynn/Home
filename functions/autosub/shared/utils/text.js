/* shared/utils/text.js
 * 文本辅助工具：
 *   - splitMixedTextToLines：把混杂文本拆成若干“可能的节点行”
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
        if (matches?.length) {
            for (const m of matches) out.push(m.trim());
            continue;
        }

        // 没有明显 scheme 时，按空格 / 逗号轻拆一层
        const parts = r.split(/\s+|,/g).filter(Boolean);
        for (const p of parts) out.push(p.trim());
    }

    return out.filter(Boolean);
}