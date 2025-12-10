/* Router.js
 * 文件作用：
 *   - 根据 UA 判断使用哪个客户端类型（clash / surge / v2ray）
 *   - 根据客户端类型选择对应的渲染方式
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* 根据 UA 判断使用哪个客户端类型
 * 返回值："clash" / "surge" / "v2ray"
 */
export function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  // UA 为空时，默认按 v2ray 处理
  if (!ua) return "v2ray";

  // Surge 客户端
  if (ua.includes("surge")) {
    return "surge";
  }

  // Clash 系客户端：clash / meta / mihomo / cfw / clash for windows
  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  // 其他全部按 v2ray(Base64) 处理
  return "v2ray";
}

/* 把原始文本转成 Base64（兼容中文） */
function toB64(text) {
  const t = String(text || "").trim();
  if (!t) return "";
  return btoa(unescape(encodeURIComponent(t)));
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
    return renderClash(nodes, { client, query, source });
  }

  // Surge：只输出 [Proxy] 节
  if (c === "surge") {
    return renderSurge(nodes, { client, query, source });
  }

  // 兜底：v2ray 样式订阅（原文 Base64 一层）
  return {
    body: toB64(rawText),
    contentType: "text/plain; charset=utf-8",
  };
}