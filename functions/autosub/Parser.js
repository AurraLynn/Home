/*
  Parser.js

  - 输入支持：
      • 混合文本（节点 + 说明文字）
      • 整段 base64 订阅（可多层解包）
      • 单条 URL 节点

  - 当前协议解析支持（全部调用 shared/utils 下的工具）：
      • ss          → parseSS
      • trojan      → parseTrojan
      • hysteria2   → parseHy2
      • vmess       → parseVmess
      • vless       → parseVless

  - 输出：
      • 标准化 Node[] 数组，供各客户端渲染器使用：
        {
          type: "vless" | "vmess" | "trojan" | "ss" | "hysteria2" | "unknown",
          name,
          server,
          port,
          ...各种协议字段,
          raw,    // 原始行（或生成的 raw），后面 normalize / 排重会用到
        }
*/

import { splitMixedTextToLines } from "./shared/utils/text.js";
import { parseSS } from "./shared/utils/ss.js";
import { parseTrojan } from "./shared/utils/trojan.js";
import { parseHy2 } from "./shared/utils/hy2.js";
import { parseVmess } from "./shared/utils/vmess.js";
import { parseVless } from "./shared/utils/vless.js";

/* 检测文本中是否已经包含任意一种节点协议 */
function containsNodeProtocol(text) {
  const t = String(text || "").toLowerCase();
  return (
    t.includes("ss://") ||
    t.includes("vmess://") ||
    t.includes("vless://") ||
    t.includes("trojan://") ||
    t.includes("hysteria2://") ||
    t.includes("hy2://") ||
    t.includes("hysteria://")
  );
}

/* 安全 base64 解码（兼容 UTF-8） */
function safeAtob(b64) {
  if (!b64) return "";
  const s = String(b64).trim();
  try {
    // Workers 环境内置 atob；escape / decodeURIComponent 解决 UTF-8 问题
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

/*
  尝试对整段文本做「多层 base64 解包」

  逻辑：
    1) 如果原文已经包含 ss:// / vmess:// / vless:// ... → 直接返回原文
    2) 否则，如果看起来是 base64（只有 A-Za-z0-9+/=）：
        最多解 3 层，每解一层检查一次是否出现协议串
*/
function tryDecodeSubscriptionText(raw, maxDepth = 3) {
  let text = String(raw || "").trim();
  if (!text) return text;

  if (containsNodeProtocol(text)) return text;

  let cur = text;
  for (let i = 0; i < maxDepth; i++) {
    const base64ish = /^[A-Za-z0-9+/=]+$/.test(cur.replace(/\s+/g, ""));
    if (!base64ish) break;

    const decoded = safeAtob(cur);
    if (!decoded) break;

    if (containsNodeProtocol(decoded)) {
      return decoded;
    }

    cur = decoded;
  }

  return text;
}

/* 尝试解析「整行 JSON 节点」：{"type":"vless","server":"...","port":...,...} */
function tryParseJsonNode(line) {
  const text = String(line || "").trim();
  if (!text.startsWith("{") || !text.endsWith("}")) return null;

  let obj = null;
  try {
    obj = JSON.parse(text);
  } catch {
    // 粗暴兼容：把单引号替成双引号再试一次（简单 clash 对象形式）
    try {
      obj = JSON.parse(text.replace(/'/g, '"'));
    } catch {
      return null;
    }
  }

  if (!obj || typeof obj !== "object") return null;

  const type =
    (obj.type || obj.protocol || obj.proto || "").toString().toLowerCase();
  if (!type) return null;

  const server =
    obj.server || obj.add || obj.address || obj.host || obj.servername || "";
  const port = Number(obj.port || obj.server_port || obj.serverPort || 0) || 0;

  let name =
    obj.name ||
    obj.ps ||
    obj.remarks ||
    (server && port ? `${server}:${port}` : "");

  return {
    ...obj,
    type,
    server,
    port,
    name: name || "",
    raw: obj.raw || text,
  };
}

/* 主入口：把任意原始文本转成 Node[] */
export function parseAnythingToNodes(rawText) {
  const result = [];

  if (!rawText || !String(rawText).trim()) {
    return result;
  }

  // 1) 对整段文本做一次「订阅解包」
  const decodedText = tryDecodeSubscriptionText(rawText);

  // 2) 按行拆分（支持 \r\n / \n 等）
  const lines = splitMixedTextToLines(decodedText);

  for (let rawLine of lines) {
    const line = String(rawLine || "").trim();
    if (!line) continue;

    // 跳过明显注释行
    if (line.startsWith("#") || line.startsWith("//")) continue;

    // ===== 1) JSON 节点行 =====
    const jsonNode = tryParseJsonNode(line);
    if (jsonNode) {
      result.push(jsonNode);
      continue;
    }

    const lower = line.toLowerCase();

    // ===== 2) 协议 URL：ss:// =====
    if (lower.startsWith("ss://")) {
      const n = parseSS(line);
      result.push(
        n
          ? { ...n, type: "ss", raw: n.raw || line }
          : { type: "ss", raw: line },
      );
      continue;
    }

    // ===== 3) 协议 URL：trojan:// =====
    if (lower.startsWith("trojan://")) {
      const n = parseTrojan(line);
      result.push(
        n
          ? { ...n, type: "trojan", raw: n.raw || line }
          : { type: "trojan", raw: line },
      );
      continue;
    }

    // ===== 4) 协议 URL：hysteria2 / hy2 =====
    if (
      lower.startsWith("hysteria2://") ||
      lower.startsWith("hy2://") ||
      lower.startsWith("hysteria://")
    ) {
      const n = parseHy2(line);
      result.push(
        n
          ? { ...n, type: "hysteria2", raw: n.raw || line }
          : { type: "hysteria2", raw: line },
      );
      continue;
    }

    // ===== 5) 协议 URL：vmess:// =====
    if (lower.startsWith("vmess://")) {
      const n = parseVmess(line);
      result.push(
        n
          ? { ...n, type: "vmess", raw: n.raw || line }
          : { type: "vmess", raw: line },
      );
      continue;
    }

    // ===== 6) 协议 URL：vless:// =====
    if (lower.startsWith("vless://")) {
      const n = parseVless(line);
      result.push(
        n
          ? { ...n, type: "vless", raw: n.raw || line }
          : { type: "vless", raw: line },
      );
      continue;
    }

    // ===== 7) 其它未知行：保留 raw，标记成 unknown，方便以后扩展 / 调试 =====
    result.push({
      type: "unknown",
      raw: line,
    });
  }

  return result;
}