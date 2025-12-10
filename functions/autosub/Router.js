/* Router.js
 * 职责：
 *   - 根据 UA 判断使用哪个客户端类型（clash / surge / v2ray）
 *   - 根据客户端类型选择对应的渲染方式
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* 根据 UA 判断使用哪个客户端类型
 * 返回值："clash" / "surge" / "v2ray"
 *
 * 约定：
 *   - 只对 Clash 系 & Surge 做 UA 识别
 *   - 其他全部兜底为 v2ray (Base64)
 */
export function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  // UA 为空：兜底 v2ray
  if (!ua) return "v2ray";

  // Surge（包括 macOS / iOS）
  if (ua.includes("surge")) {
    return "surge";
  }

  // Clash 系（clash / meta / mihomo / cfw / clash for windows）
  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  // 其他全部当 v2ray(Base64)
  return "v2ray";
}

/* 把原始文本转成 Base64（兼容中文） */
function toB64(text) {
  const t = String(text || "").trim();
  if (!t) return "";
  return btoa(unescape(encodeURIComponent(t)));
}

/* 判断文本里是否包含任意一种节点协议前缀 */
function containsNodeProtocol(str) {
  if (!str) return false;
  const t = String(str).toLowerCase();
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

/* 安全 Base64 解码，用于“是否像订阅串”的检测 */
function safeAtobDetect(b64) {
  if (!b64) return "";
  const s = String(b64).trim();
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch (e) {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

/* 判断一段文本是否为“Base64 订阅串”
 * 条件：
 *   - 自身不含协议前缀
 *   - 解码后出现 ss:// / vmess:// / vless:// / trojan:// / hy2:// 等
 */
function looksLikeBase64Subscription(raw) {
  const text = String(raw || "").trim();
  if (!text) return false;

  // 自身已经是 URL 节点串，就不是“订阅 Base64”
  if (containsNodeProtocol(text)) return false;

  // 大致限定为 Base64 字符集
  const compact = text.replace(/\s+/g, "");
  const base64ish = /^[A-Za-z0-9+/=]+$/.test(compact);
  if (!base64ish) return false;

  const decoded = safeAtobDetect(compact);
  if (!decoded) return false;

  return containsNodeProtocol(decoded);
}

/* 根据客户端类型，选择渲染输出格式
 * 参数：
 *   - nodes: 解析后的节点列表
 *   - client: "clash" / "surge" / "v2ray"
 *   - rawText: 原始文本（给 v2ray Base64 用）
 */
export function routeAndRender(
  nodes,
  {
    client = "v2ray",
    rawText = "",
    query = {},
    source = "",
  } = {},
) {
  const c = String(client || "v2ray").toLowerCase();

  // Clash：输出简易完整配置
  if (c === "clash") {
    return renderClash(nodes, { client, query, source, rawText });
  }

  // Surge：只输出 [Proxy] 段
  if (c === "surge") {
    return renderSurge(nodes, { client, query, source, rawText });
  }

  // 兜底：v2ray 样式订阅
  // 防止“已经是 Base64 订阅串”被二次 Base64：
  //   - 如果原文看起来就是 Base64 订阅：原样返回
  //   - 否则：把原文当作明文节点列表，Base64 一层
  const original = String(rawText || "");
  let out = "";

  if (looksLikeBase64Subscription(original)) {
    out = original.trim();
  } else {
    out = toB64(original);
  }

  return {
    body: out,
    contentType: "text/plain; charset=utf-8",
  };
}
