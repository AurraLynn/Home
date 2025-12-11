/*
 * 文件路径：functions/autosub/shared/utils/text.js
 * 文件作用：
 *   - 文本预处理与拆分工具
 *   - 从混合内容中尽可能提取出各类协议链接片段
 *   - 为 Parser 提供按行/片段的基础输入（Node 解析前置步骤）
 */

/*
 * 正则：匹配常见代理协议的完整 URL 片段
 *   - 支持：ss / ssr / vmess / vless / trojan / hysteria2 / hy2 / hysteria / tuic / snell / socks5 / http / https
 *   - 形式：scheme://紧接非空白字符，一直到下一个空白为止
 */
const SCHEME_RE =
    /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\/[^\s]+/gi;

/*
 * 函数：splitMixedTextToLines
 *
 * 功能：
 *   - 将一整段混合文本拆分成“候选行数组”，供后续逐条解析
 *   - 规则：
 *       1. 按行拆分（\r\n → \n）
 *       2. 如果一行中包含协议 URL（SCHEME_RE 能匹配到）：
 *            • 把行内所有匹配到的 URL 单独提取出来
 *       3. 如果没有协议 URL：
 *            • 按空白字符 / 逗号轻度拆分
 *            • 不再按分号拆分（避免误伤某些内容）
 *
 * 返回：
 *   - string[]：每个元素都是一段候选字符串，后续由 Parser 判断协议类型
 */
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

        // 没 scheme 时，轻度拆分（不包含 ;）
        const parts = r.split(/\s+|,/g).filter(Boolean);
        for (const p of parts) out.push(p.trim());
    }

    return out.filter(Boolean);
}