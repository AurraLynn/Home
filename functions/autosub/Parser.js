/*
  Parser.js

  - 输入支持：
      • 混合文本（节点 + 说明文字）
      • 整段 base64 订阅（可多层解包）
      • 单条 URL 节点
      • Clash 内联 proxies 对象行：
          - { name: 'xxx', type: vless, server: example.com, port: 443, uuid: xxxx, ... }

  - 当前协议解析支持：
      • ss          → parseSS
      • trojan      → parseTrojan
      • hysteria2   → parseHy2
      • vmess       → parseVmess
      • vless       → parseVless

  - 输出：
      • 标准化 Node[] 数组，供各客户端渲染器使用
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

  // 太短的一般不是
  if (t.length < 16) return false;
  // base64 合法字符
  if (!/^[A-Za-z0-9+/_\-=]+$/.test(t)) return false;
  // 已经有 :// 的，说明更像 URL
  if (t.includes("://")) return false;

  return true;
}

/**
 * urlsafe base64 解码（兼容 -/_）
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
 * 最多解 maxDepth 层（防止死循环）
 */
function decodeMaybeToScheme(s, maxDepth = 2) {
  let cur = String(s || "").trim();
  for (let depth = 0; depth < maxDepth; depth++) {
    if (!isLikelyBase64(cur)) return "";
    const decoded = b64DecodeUrlSafe(cur);
    if (!decoded || decoded === cur) return "";

    // 解出来如果已经包含我们关心的协议，就返回
    if (SCHEME_RE.test(decoded)) {
      return decoded;
    }

    // 否则继续尝试下一层
    cur = decoded;
  }
  return "";
}

/**
 * 解析 Clash 内联 proxies 行：
 *   - { name: 'xxx', type: vless, server: example.com, port: 443, uuid: xxxx, ... }
 *
 * 返回一个普通对象 { name, type, server, port, uuid, ... }，解析失败返回 null
 */
function parseClashInlineObject(line) {
  const start = line.indexOf("{");
  const end = line.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;

  const body = line.slice(start + 1, end);
  const segs = [];
  let cur = "";
  let inSingle = false;
  let inDouble = false;

  for (let i = 0; i < body.length; i++) {
    const ch = body[i];
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      cur += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      cur += ch;
      continue;
    }
    if (ch === "," && !inSingle && !inDouble) {
      if (cur.trim()) segs.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) segs.push(cur.trim());

  const obj = {};
  for (const seg of segs) {
    const idx = seg.indexOf(":");
    if (idx === -1) continue;
    const rawKey = seg.slice(0, idx).trim();
    let key = rawKey;
    // 去掉可能的引号
    if (
      (key.startsWith("'") && key.endsWith("'")) ||
      (key.startsWith('"') && key.endsWith('"'))
    ) {
      key = key.slice(1, -1);
    }
    let val = seg.slice(idx + 1).trim();

    // 去掉尾部多余逗号（正常不会有）
    if (val.endsWith(",")) val = val.slice(0, -1).trim();

    // 去掉引号
    if (
      (val.startsWith("'") && val.endsWith("'")) ||
      (val.startsWith('"') && val.endsWith('"'))
    ) {
      val = val.slice(1, -1);
      obj[key] = val;
      continue;
    }

    const lower = val.toLowerCase();
    if (lower === "true" || lower === "false") {
      obj[key] = lower === "true";
      continue;
    }

    if (/^-?\d+(?:\.\d+)?$/.test(val)) {
      obj[key] = Number(val);
      continue;
    }

    obj[key] = val;
  }

  if (!obj.type) return null;
  return obj;
}

/**
 * Clash 内联对象 → 标准 Node
 */
function nodeFromClashInline(obj, rawLine) {
  const typeRaw = String(obj.type || "").toLowerCase();
  let t = typeRaw;
  if (t === "hy2" || t === "hysteria") t = "hysteria2";

  const server = obj.server || obj.add || "";
  const port = obj.port || obj.server_port || 0;
  const name = obj.name || obj.ps || "";

  const base = {
    type: t,
    raw: rawLine,
    name,
    server,
    port,
  };

  if (!server || !port) {
    return base;
  }

  if (t === "ss") {
    return {
      ...base,
      cipher: obj.cipher || obj.method || "",
      password: obj.password || "",
      plugin: obj.plugin,
      pluginOpts: obj["plugin-opts"],
    };
  }

  if (t === "trojan") {
    return {
      ...base,
      password: obj.password || obj.pwd || "",
      sni: obj.sni || obj.servername,
      network: obj.network,
      path: obj.path,
      skipCertVerify:
        typeof obj["skip-cert-verify"] === "boolean"
          ? obj["skip-cert-verify"]
          : undefined,
      realityPublicKey: obj["public-key"],
      realityShortId: obj["short-id"],
      realitySpiderX: obj["spider-x"],
    };
  }

  if (t === "vmess") {
    return {
      ...base,
      uuid: obj.uuid || obj.id || "",
      alterId: obj.aid || obj.alterId || 0,
      cipher: obj.cipher || obj.scy || obj.security,
      network: obj.network || obj.net,
      host: obj.host,
      path: obj.path,
      tls: obj.tls === true,
      sni: obj.sni || obj.servername,
    };
  }

  if (t === "vless") {
    return {
      ...base,
      uuid: obj.uuid || obj.id || "",
      flow: obj.flow,
      udp: typeof obj.udp === "boolean" ? obj.udp : undefined,
      tls: obj.tls === true,
      security: obj.tls ? "tls" : "",
      sni: obj.sni || obj.servername,
      alpn: obj.alpn,
      clientFingerprint: obj["client-fingerprint"],
      realityPublicKey: obj["public-key"],
      realityShortId: obj["short-id"],
      realitySpiderX: obj["spider-x"],
      network: obj.network,
      host: obj.host,
      path: obj.path,
    };
  }

  if (t === "hysteria2") {
    return {
      ...base,
      password: obj.auth || obj.password || "",
      ports: obj.ports,
      sni: obj.sni,
      udp: typeof obj.udp === "boolean" ? obj.udp : undefined,
      skipCertVerify:
        typeof obj["skip-cert-verify"] === "boolean"
          ? obj["skip-cert-verify"]
          : undefined,
      obfs: obj.obfs,
    };
  }

  return base;
}

/**
 * 核心解析器：
 *   原始文本（可以是多行 / 混合内容 / 纯 base64 / Clash YAML）
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

    // ===== 1) 明确的 scheme 行（URL 节点） =====

    // ss://
    if (line.startsWith("ss://")) {
      const n = parseSS(line);
      nodes.push(
        n
          ? { ...n, type: "ss", raw: n.raw || line }
          : { type: "ss", raw: line }
      );
      continue;
    }

    // vmess://
    if (line.toLowerCase().startsWith("vmess://")) {
      const n = parseVmess(line);
      nodes.push(
        n
          ? { ...n, type: "vmess", raw: n.raw || line }
          : { type: "vmess", raw: line }
      );
      continue;
    }

    // vless://
    if (line.toLowerCase().startsWith("vless://")) {
      const n = parseVless(line);
      nodes.push(
        n
          ? { ...n, type: "vless", raw: n.raw || line }
          : { type: "vless", raw: line }
      );
      continue;
    }

    // trojan://
    if (line.toLowerCase().startsWith("trojan://")) {
      const n = parseTrojan(line);
      nodes.push(
        n
          ? { ...n, type: "trojan", raw: n.raw || line }
          : { type: "trojan", raw: line }
      );
      continue;
    }

    // hysteria2 / hy2 / hysteria://
    {
      const l = line.toLowerCase();
      if (
        l.startsWith("hysteria2://") ||
        l.startsWith("hy2://") ||
        l.startsWith("hysteria://")
      ) {
        const n = parseHy2(line);
        nodes.push(
          n
            ? { ...n, type: "hysteria2", raw: n.raw || line }
            : { type: "hysteria2", raw: line }
        );
        continue;
      }
    }

    // ===== 2) Clash YAML 内联 proxies 行 =====
    if (line.includes("{") && line.includes("type:")) {
      const obj = parseClashInlineObject(line);
      if (obj && obj.type) {
        const t = String(obj.type || "").toLowerCase();
        if (
          t === "ss" ||
          t === "vmess" ||
          t === "vless" ||
          t === "trojan" ||
          t === "hysteria2" ||
          t === "hysteria" ||
          t === "hy2"
        ) {
          const node = nodeFromClashInline(obj, line);
          nodes.push(node);
          continue;
        }
      }
    }

    // ===== 3) 没有明显 scheme：尝试当 base64 订阅解包 =====

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

    // ===== 4) 兜底未知：保留 raw，方便后续调试/扩展 =====
    nodes.push({ type: "unknown", raw: line });
  }

  return nodes;
}