import { splitMixedTextToLines } from "./shared/utils/text.js";

export function parseAnythingToNodes(rawText) {
    const text = String(rawText || "");
    const lines = splitMixedTextToLines(text);

    const nodes = [];

    for (const line of lines) {
        const s = line.trim();
        if (!s) continue;

        if (s.startsWith("ss://")) nodes.push({ type: "ss", raw: s });
        else if (s.startsWith("vmess://")) nodes.push({ type: "vmess", raw: s });
        else if (s.startsWith("vless://")) nodes.push({ type: "vless", raw: s });
        else if (s.startsWith("trojan://")) nodes.push({ type: "trojan", raw: s });
        else nodes.push({ type: "unknown", raw: s });
    }

    return nodes;
}