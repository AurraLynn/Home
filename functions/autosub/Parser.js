import { splitLines, looksLikeBase64Subscription } from "./shared/utils/text.js";
import { safeB64Decode } from "./shared/utils/base64.js";

function parseLine(line) {
    const s = line.trim();
    if (!s) return null;

    // 这里只做“占位识别”
    if (/^ss:\/\//i.test(s)) return { type: "ss", extra: { raw: s } };
    if (/^ssr:\/\//i.test(s)) return { type: "ssr", extra: { raw: s } };
    if (/^vmess:\/\//i.test(s)) return { type: "vmess", extra: { raw: s } };
    if (/^vless:\/\//i.test(s)) return { type: "vless", extra: { raw: s } };
    if (/^trojan:\/\//i.test(s)) return { type: "trojan", extra: { raw: s } };
    if (/^hysteria2?:\/\//i.test(s)) return { type: "hy", extra: { raw: s } };

    return null;
}

export function parseAnythingToNodes(rawText = "") {
    let text = rawText || "";

    // 整串 base64 订阅先解一次
    if (looksLikeBase64Subscription(text)) {
        const decoded = safeB64Decode(text.trim());
        if (decoded) text = decoded;
    }

    const lines = splitLines(text);
    const nodes = [];

    for (const line of lines) {
        const n = parseLine(line);
        if (n) nodes.push(n);
    }

    return nodes;
}