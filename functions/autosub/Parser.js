// Parser - 输入支持：混合文本 / base64 订阅 / ss, vmess, vless, trojan 等 URL
// 输出：标准化 Node 数组（目前 Clash 渲染支持 ss、trojan）

import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";

// 可识别的 scheme（用于 base64 解出来后判断）
const SCHEME_RE =
    /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\//i;

// 粗略判断一段文本是否“像 base64”
function isLikelyBase64(s) {
    if (!s) return false;
    const t = String(s).trim();

    // 太短没意义
    if (t.length < 12) return false;

    // 必须是 base64 字符范围（含 urlsafe）
    if (!/^[A-Za-z0-9+/_\-=]+$/.test(t)) return false;

    // 避免把明文 ss:// 之类误判
    if (t.includes("://")) return false;

    return true;
}

// 尽量安全地 base64 解码（兼容 urlsafe）
function b64DecodeUrlSafe(input) {
    if (!input) return "";
    let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    try {
        // Worker 环境有 atob
        return decodeURIComponent(escape(atob(s)));
    } catch {
        try {
            return atob(s);
        } catch {
            return "";
        }
    }
}

// 尝试解 1~maxDepth 层 base64，直到出现我们认识的 scheme
function decodeMaybeToScheme(s, maxDepth = 2) {
    let cur = String(s || "").trim();

    for (let i = 0; i < maxDepth; i++) {
        if (!isLikelyBase64(cur)) return "";

        const decoded = b64DecodeUrlSafe(cur);
        if (!decoded || decoded === cur) return "";

        // 解出来含 scheme：命中
        if (SCHEME_RE.test(decoded)) return decoded;

        // 否则继续下一层
        cur = decoded.trim();
    }

    return "";
}

// 原始文本 -> Node[]
// - 支持混合：节点 + 文本 + base64
// - 对没有 :// 的行尝试 base64 解包回灌队列
export function parseAnythingToNodes(rawText) {
    const text = String(rawText || "");
    const initialLines = splitMixedTextToLines(text);

    const queue = [...initialLines];
    const nodes = [];

    // 防止重复/死循环
    const seenLine = new Set();

    while (queue.length) {
        const line = String(queue.shift() || "").trim();
        if (!line) continue;

        if (seenLine.has(line)) continue;
        seenLine.add(line);

        // 1) 直接有 scheme 的，按协议分发
        if (line.startsWith("ss://")) {
            const n = parseSS(line);
            nodes.push(n || { type: "ss", raw: line });
            continue;
        }

        if (line.startsWith("vmess://")) {
            // 先只保留 raw，后面补 parseVmess
            nodes.push({ type: "vmess", raw: line });
            continue;
        }

        if (line.startsWith("vless://")) {
            // 同上，先占位
            nodes.push({ type: "vless", raw: line });
            continue;
        }

        if (line.startsWith("trojan://")) {
            // ★ 关键：真正调用 parseTrojan 拆字段
            const n = parseTrojan(line);
            nodes.push(n || { type: "trojan", raw: line });
            continue;
        }

        // 2) 没有 scheme 的行：尝试当 base64 解析
        if (!line.includes("://") && isLikelyBase64(line)) {
            const decoded = decodeMaybeToScheme(line, 2);

            if (decoded) {
                // 解出来可能是一段混合文本/多节点，再丢回队列
                const more = splitMixedTextToLines(decoded);
                for (const m of more) {
                    const v = String(m || "").trim();
                    if (v && !seenLine.has(v)) queue.push(v);
                }
                continue;
            }
        }

        // 3) 兜底未知
        nodes.push({ type: "unknown", raw: line });
    }

    return nodes;
}
