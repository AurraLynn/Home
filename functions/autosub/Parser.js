/* Parser.js
 *
 * 职责：
 *   - 统一解析入口：任意奇怪文本 → 标准 Node[]
 *   - 支持：
 *       • 整串 base64 订阅（可多层解包）
 *       • 单条 base64 节点
 *       • 混合文本 / 说明文字
 *       • URL 节点：ss / trojan / vmess / vless / hy2(hysteria2/hysteria)
 *       • 简单 JSON 行：{"type":"vless","server":"...","port":...}
 */

import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";
import { parseHy2 } from "./shared/utils/hy2.js";
import { parseVmess } from "./shared/utils/vmess.js";
import { parseVless } from "./shared/utils/vless.js";

/* 安全 Base64 解码（支持 URL-Safe） */
function safeBase64Decode(str) {
    try {
        const s = String(str || "").replace(/\s+/g, "");
        if (!s) return "";
        let norm = s.replace(/-/g, "+").replace(/_/g, "/");
        const pad = norm.length % 4;
        if (pad === 2) norm += "==";
        else if (pad === 3) norm += "=";
        else if (pad === 1) norm += "===";

        // Workers 环境有 atob
        return decodeURIComponent(
            escape(atob(norm)),
        );
    } catch {
        return "";
    }
}

/* 粗略判断一行看起来像 base64 */
function looksLikeBase64(str) {
    const s = String(str || "").replace(/\s+/g, "");
    if (!s || s.length < 8) return false;
    if (/[^A-Za-z0-9+/=_-]/.test(s)) return false;
    return true;
}

/* 解析可能的 JSON 节点（Clash proxies 行） */
function tryParseJsonNode(line) {
    const text = String(line || "").trim();
    if (!text.startsWith("{") || !text.endsWith("}")) return null;

    let obj = null;
    try {
        obj = JSON.parse(text);
    } catch {
        // 粗暴把单引号替成双引号再试一次（兼容少量行内 JSON）
        try {
            obj = JSON.parse(
                text.replace(/'/g, '"'),
            );
        } catch {
            return null;
        }
    }

    if (!obj || typeof obj !== "object") return null;

    const type = String(obj.type || obj.protocol || "").toLowerCase();
    if (!type) return null;

    const server =
        obj.server || obj.add || obj.address || obj.host || "";
    const port = Number(obj.port || obj.server_port || 0);

    let name =
        obj.name ||
        obj.ps ||
        obj.remarks ||
        (server && port ? `${server}:${port}` : "");

    const node = {
        ...obj,
        type,
        server,
        port,
        name: name || "",
        raw: obj.raw || text,
    };

    return node;
}

/* 统一解析入口：原始文本 → Node[] */
export function parseAnythingToNodes(rawText = "") {
    const nodes = [];
    const queue = [];
    const seenText = new Set();

    const first = String(rawText || "").trim();
    if (!first) return [];

    queue.push(first);

    while (queue.length) {
        const curText = queue.shift();
        if (!curText) continue;

        const key = curText.length > 2048 ? curText.slice(0, 2048) : curText;
        if (seenText.has(key)) continue;
        seenText.add(key);

        const items = splitMixedTextToLines(curText);

        for (const item of items) {
            const line = String(item || "").trim();
            if (!line) continue;

            const lower = line.toLowerCase();

            // ===== 1) 纯 base64 行：尝试解一层，看里面是不是节点/订阅 =====
            if (!lower.includes("://") && looksLikeBase64(line)) {
                const decoded = safeBase64Decode(line);
                if (decoded && decoded !== line) {
                    // 如果解出来包含协议/JSON/Clash 就再进队列递归解析
                    if (
                        /ss:\/\//i.test(decoded) ||
                        /vmess:\/\//i.test(decoded) ||
                        /vless:\/\//i.test(decoded) ||
                        /trojan:\/\//i.test(decoded) ||
                        /hysteria2?:\/\//i.test(decoded) ||
                        /"type"\s*:\s*"/i.test(decoded) ||
                        /\bproxies\b/i.test(decoded)
                    ) {
                        queue.push(decoded);
                        continue;
                    }
                }
            }

            // ===== 2) JSON 行：Clash 内联 proxy 对象 =====
            if (line[0] === "{" && line.endsWith("}")) {
                const jsonNode = tryParseJsonNode(line);
                if (jsonNode) {
                    nodes.push(jsonNode);
                    continue;
                }
            }

            // ===== 3) URL 协议：ss / trojan / vmess / vless / hy2 =====
            let n = null;
            if (lower.startsWith("ss://")) {
                n = parseSS(line);
            } else if (lower.startsWith("vmess://")) {
                n = parseVmess(line);
            } else if (lower.startsWith("vless://")) {
                n = parseVless(line);
            } else if (lower.startsWith("trojan://")) {
                n = parseTrojan(line);
            } else if (
                lower.startsWith("hysteria2://") ||
                lower.startsWith("hy2://") ||
                lower.startsWith("hysteria://")
            ) {
                n = parseHy2(line);
            }

            if (n) {
                nodes.push(n);
                continue;
            }

            // ===== 4) 兜底未知：保留 raw，方便后续调试/扩展 =====
            nodes.push({ type: "unknown", raw: line });
        }
    }

    return nodes;
}