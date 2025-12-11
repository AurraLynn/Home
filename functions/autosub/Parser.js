/* Parser.js
 * 文件作用：
 *   - 接收各种输入（订阅 base64 / 节点列表 / JSON）
 *   - 输出统一节点数组：[{ type, name, server, port, raw, ... }]
 */

import { parseSSUrl } from "./shared/utils/ss.js";
import { parseVmessUrlOrJson } from "./shared/utils/vmess.js";
import { parseVlessUrl } from "./shared/utils/vless.js";
import { parseTrojanUrl } from "./shared/utils/trojan.js";
import { parseHy2Url } from "./shared/utils/hy2.js";

/* 尝试最多 3 层 Base64 解出来的订阅文本 */
function tryDecodeBase64Subscription(raw) {
    let text = String(raw || "").trim();
    if (!text) return text;

    for (let i = 0; i < 3; i++) {
        const compact = text.replace(/\s+/g, "");
        if (!/^[A-Za-z0-9+/=]+$/.test(compact)) break;

        try {
            const decoded = decodeURIComponent(escape(atob(compact)));
            const lower = decoded.toLowerCase();
            if (
                lower.includes("ss://") ||
                lower.includes("vmess://") ||
                lower.includes("vless://") ||
                lower.includes("trojan://") ||
                lower.includes("hysteria2://") ||
                lower.includes("hy2://")
            ) {
                return decoded;
            }
            text = decoded;
        } catch {
            break;
        }
    }

    return text;
}

/* 尝试把一行当作 JSON 节点解析 */
function tryParseJsonLine(line) {
    const s = line.trim();
    if (!s.startsWith("{") || !s.endsWith("}")) return null;

    try {
        const obj = JSON.parse(s);
        if (!obj || typeof obj !== "object") return null;

        return {
            ...obj,
            raw: s,
            type: (obj.type || obj.protocol || obj.net || "").toLowerCase(),
            name: obj.name || obj.ps || obj.remark || "",
        };
    } catch {
        return null;
    }
}

/* 解析单行：按协议类型分发到对应解析器 */
function parseSingleLine(line) {
    const s = String(line || "").trim();
    if (!s) return null;

    const asJson = tryParseJsonLine(s);
    if (asJson) return asJson;

    if (s.startsWith("ss://")) {
        const node = parseSSUrl(s);
        return node ? { ...node, type: "ss", raw: s } : null;
    }

    if (s.startsWith("vmess://")) {
        const node = parseVmessUrlOrJson(s);
        return node ? { ...node, type: "vmess", raw: s } : null;
    }

    if (s.startsWith("vless://")) {
        const node = parseVlessUrl(s);
        return node ? { ...node, type: "vless", raw: s } : null;
    }

    if (s.startsWith("trojan://")) {
        const node = parseTrojanUrl(s);
        return node ? { ...node, type: "trojan", raw: s } : null;
    }

    const lower = s.toLowerCase();
    if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
        const node = parseHy2Url(s);
        return node ? { ...node, type: "hysteria2", raw: s } : null;
    }

    return null;
}

/* 总入口：原始文本 → 节点数组 */
export function parseAnythingToNodes(rawInput) {
    if (!rawInput) return [];

    const decoded = tryDecodeBase64Subscription(rawInput);
    const text = decoded || String(rawInput || "");

    const lines = text
        .replace(/\r\n/g, "\n")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);

    const nodes = [];

    for (const line of lines) {
        const node = parseSingleLine(line);
        if (node) nodes.push(node);
    }

    return nodes;
}