import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";
import { renderQX } from "./renderers/qx.js";

/**
 * Router
 * - 按 client 选择对应渲染器
 * - 你要求：识别不到默认 v2ray(Base64)
 * - 你要求：stash 不需要，所以这里不再 import/route stash
 */
export function routeAndRender(nodes, { client = "v2ray", rawText = "" } = {}) {
  const c = String(client || "v2ray").toLowerCase();

  // 默认 / 回退：v2ray base64
  if (c === "v2ray") {
    const text = String(rawText || "").trim();
    const b64 = btoa(unescape(encodeURIComponent(text)));
    return { body: b64, contentType: "text/plain; charset=utf-8" };
  }

  if (c === "clash") return renderClash(nodes);
  if (c === "surge") return renderSurge(nodes);
  if (c === "qx") return renderQX(nodes);

  // 未知 client：仍按你的规则回退 v2ray
  const text = String(rawText || "").trim();
  const b64 = btoa(unescape(encodeURIComponent(text)));
  return { body: b64, contentType: "text/plain; charset=utf-8" };
}
