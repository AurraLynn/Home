/* Router.js
 * ===============================
 * 作用：
 *   1. 根据 UA 推测 client 类型：clash / surge / v2ray
 *   2. 根据 client 选择渲染器：Clash / Surge / v2ray(Base64)
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/* 根据 UA 推测 client 类型
 *  - 含 surge        → "surge"
 *  - 含 clash/meta/... → "clash"
 *  - 其他            → "v2ray"
 */
export function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  /* UA 为空：兜底 v2ray */
  if (!ua) return "v2ray";

  /* Surge 客户端 */
  if (ua.includes("surge")) {
    return "surge";
  }

  /* Clash 系客户端：clash / meta / mihomo / cfw / clash for windows */
  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  /* 其他 UA：全部走 v2ray(Base64) */
  return "v2ray";
}

/* 文本转 Base64（UTF-8 安全处理） */
function toB64(text) {
  const t = String(text || "").trim();
  if (!t) return "";
  /* Workers 环境内置 btoa，这里用 encodeURIComponent 兼容中文 */
  return btoa(unescape(encodeURIComponent(t)));
}

/* 统一路由出口：nodes → 对应客户端格式内容
 *  - client = "clash" → Clash 简易配置
 *  - client = "surge" → Surge 仅 [Proxy]
 *  - 其它             → v2ray(Base64) 兜底
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

  /* Clash 输出：简易完整配置（含 DNS / 规则 / 代理组） */
  if (c === "clash") {
    return renderClash(nodes, { client, query, source });
  }

  /* Surge 输出：仅 [Proxy] 节点列表 */
  if (c === "surge") {
    return renderSurge(nodes, { client, query, source });
  }

  /* 兜底：v2ray 样式订阅（原文 base64 一层） */
  return {
    body: toB64(rawText),
    contentType: "text/plain; charset=utf-8",
  };
}