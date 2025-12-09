import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";

/**
 * 识别我们关心的 scheme
 * 你后续要加更多协议，这里可以扩
 */
const SCHEME_RE =
  /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\//i;

/**
 * 粗略判断一段文本是否“像 base64”
 * 目的：避免误把普通文本当 base64 解
 */
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

/**
 * urlsafe base64 decode
 */
function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");

  // padding
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  try {
    // 兼容 UTF-8
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

/**
 * 尝试解 1~2 层 base64
 * 只要某一层解出来含 scheme，就返回那一层解码结果
 */
function decodeMaybeToScheme(s, maxDepth = 2) {
  let cur = String(s || "").trim();

  for (let i = 0; i < maxDepth; i++) {
    if (!isLikelyBase64(cur)) return "";

    const decoded = b64DecodeUrlSafe(cur);
    if (!decoded || decoded === cur) return "";

    // 解出来含 scheme：命中
    if (SCHEME_RE.test(decoded)) return decoded;

    // 继续尝试下一层
    cur = decoded.trim();
  }

  return "";
}

/**
 * 入口：全形态 + 混合内容解析
 * 关键增强：
 * - 对“没有 :// 的行”尝试 base64 解码回灌
 */
export function parseAnythingToNodes(rawText) {
  const text = String(rawText || "");
  const initialLines = splitMixedTextToLines(text);

  const queue = [...initialLines];
  const nodes = [];

  // 防止重复/无限回灌
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
      nodes.push({ type: "vmess", raw: line });
      continue;
    }

    if (line.startsWith("vless://")) {
      nodes.push({ type: "vless", raw: line });
      continue;
    }

    if (line.startsWith("trojan://")) {
      nodes.push({ type: "trojan", raw: line });
      continue;
    }

    // 2) 没有 scheme 的行：尝试当 base64 解析
    if (!line.includes("://") && isLikelyBase64(line)) {
      const decoded = decodeMaybeToScheme(line, 2);

      if (decoded) {
        // 解出来可能是一段混合文本/多节点
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
