/*
  Parser.js

  - 输入支持：
      • 混合文本（节点 + 说明文字）
      • 整段 base64 订阅（可多层解包）
      • 单条 URL 节点

  - 当前协议解析支持：
      • ss          → parseSS
      • trojan      → parseTrojan
      • hysteria2   → parseHy2
      • vmess       → parseVmess
      • vless       → parseVless

  - 输出：
      • 标准化 Node[] 数组
*/

import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";
import { parseHy2 } from "./shared/utils/hy2.js";
import { parseVmess } from "./shared/utils/vmess.js";
import { parseVless } from "./shared/utils/vless.js";

/**
 * 用于 base64 解包时检测是否已经出现我们关心的协议 scheme
 */
const SCHEME_RE =
  /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\//i;

/**
 * 粗略判断一段文本是否“像 base64”
 */
function isLikelyBase64(s) {
  if (!s) return false;
  const t = String(s).trim();

  if (t.length < 16) return false;
  if (!/^[A-Za-z0-9+/_\-=]+$/.test(t)) return false;
  if (t.includes("://")) return false;

  return true;
}

/**
 * urlsafe base64 解码
 */
function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");

  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  try {
    return atob(s);
  } catch {
    return "";
  }
}

/**
 * 尝试把“像 base64”的文本解码成带 scheme 的内容
 */
function decodeMaybeToScheme(s, maxDepth = 2) {
  let cur = String(s || "").trim();
  for (let depth = 0; depth < maxDepth; depth++) {
    if (!isLikelyBase64(cur)) return "";
    const decoded = b64DecodeUrlSafe(cur);
    if (!decoded || decoded === cur) return "";

    if (SCHEME_RE.test(decoded)) {
      return decoded;
    }
    cur = decoded;
  }
  return "";
}

/**
 * 核心解析器：
 *   原始文本（可以是多行 / 混合内容 / 纯 base64）
 *   → Node[]（统一结构，把能识别的协议尽量解析出来）
 */
export function parseAnythingToNodes(rawText) {
  const text = String(rawText || "");
  const initialLines = splitMixedTextToLines(text);

  const queue = [...initialLines];
  const nodes = [];
  const seenLine = new Set();

  while (queue.length) {
    const line = String(queue.shift() || "").trim();
    if (!line) continue;
    if (seenLine.has(line)) continue;
    seenLine.add(line);

    // ===== 1) 明确的 scheme 行 =====

    // ss://
    if (line.startsWith("ss://")) {
      const n = parseSS(line);
      nodes.push(n || { type: "ss", raw: line });
      continue;
    }

    // vmess://
    if (line.startsWith("vmess://")) {
      const n = parseVmess(line);
      nodes.push(n || { type: "vmess", raw: line });
      continue;
    }

    // vless://
    if (line.toLowerCase().startsWith("vless://")) {
      const n = parseVless(line);
      nodes.push(n || { type: "vless", raw: line });
      continue;
    }

    // trojan://
    if (line.toLowerCase().startsWith("trojan://")) {
      const n = parseTrojan(line);
      nodes.push(n || { type: "trojan", raw: line });
      continue;
    }

    // hysteria2 / hy2 / hysteria
    if (
      line.toLowerCase().startsWith("hysteria2://") ||
      line.toLowerCase().startsWith("hy2://") ||
      line.toLowerCase().startsWith("hysteria://")
    ) {
      const n = parseHy2(line);
      nodes.push(n || { type: "hysteria2", raw: line });
      continue;
    }

    // ===== 2) 没有 scheme 的行：尝试当 base64 解析成订阅 =====

    if (!line.includes("://") && isLikelyBase64(line)) {
      const decoded = decodeMaybeToScheme(line, 3);

      if (decoded) {
        const more = splitMixedTextToLines(decoded);
        for (const m of more) {
          const v = String(m || "").trim();
          if (v && !seenLine.has(v)) queue.push(v);
        }
        continue;
      }
    }

    // ===== 3) 兜底未知 =====
    nodes.push({ type: "unknown", raw: line });
  }

  return nodes;
}