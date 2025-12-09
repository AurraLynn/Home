/*
  - 输入支持：
      混合文本（节点 + 普通文字）
      整串 base64 订阅（内含多个节点）
      单条 URL：ss://、vmess://、vless://、trojan://、hysteria2://、hy2://

  - 输出：
      标准化 Node 数组
      当前 Clash 渲染已支持协议：
      ss
      trojan
      hysteria2(hy2)

  - client 行为示例：
      /autosub?id=你的id&client=clash
*/

import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";
import { parseHy2 } from "./shared/utils/hy2.js";

const SCHEME_RE =
  /\b(?:ss|ssr|vmess|vless|trojan|hysteria2|hy2|hysteria|tuic|snell|socks5|http|https):\/\//i;

function isLikelyBase64(s) {
  if (!s) return false;
  const t = String(s).trim();
  if (t.length < 12) return false;
  if (!/^[A-Za-z0-9+/_\-=]+$/.test(t)) return false;
  if (t.includes("://")) return false;
  return true;
}

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

function decodeMaybeToScheme(s, maxDepth = 2) {
  let cur = String(s || "").trim();

  for (let i = 0; i < maxDepth; i++) {
    if (!isLikelyBase64(cur)) return "";

    const decoded = b64DecodeUrlSafe(cur);
    if (!decoded || decoded === cur) return "";

    if (SCHEME_RE.test(decoded)) return decoded;

    cur = decoded.trim();
  }

  return "";
}

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
      const n = parseTrojan(line);
      nodes.push(n || { type: "trojan", raw: line });
      continue;
    }

    if (line.startsWith("hysteria2://") || line.startsWith("hy2://")) {
      const n = parseHy2(line);
      nodes.push(n || { type: "hysteria2", raw: line });
      continue;
    }

    if (!line.includes("://") && isLikelyBase64(line)) {
      const decoded = decodeMaybeToScheme(line, 2);
      if (decoded) {
        const more = splitMixedTextToLines(decoded);
        for (const m of more) {
          const v = String(m || "").trim();
          if (v && !seenLine.has(v)) queue.push(v);
        }
        continue;
      }
    }

    nodes.push({ type: "unknown", raw: line });
  }

  return nodes;
}
