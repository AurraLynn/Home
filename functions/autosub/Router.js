import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";
import { renderQX } from "./renderers/qx.js";
import { renderStash } from "./renderers/stash.js";

export function routeAndRender(nodes, { client = "v2ray", rawText = "" } = {}) {
  const c = String(client || "v2ray").toLowerCase();

  // v2ray 默认还是 base64 原文（保你原规则）
  if (c === "v2ray") {
    const b64 = btoa(unescape(encodeURIComponent(String(rawText || "").trim())));
    return { body: b64, contentType: "text/plain; charset=utf-8" };
  }

  if (c === "clash") return renderClash(nodes);
  if (c === "surge") return renderSurge(nodes);
  if (c === "qx") return renderQX(nodes);
  if (c === "stash") return renderStash(nodes);

  // 未知 client：回退 v2ray base64
  const b64 = btoa(unescape(encodeURIComponent(String(rawText || "").trim())));
  return { body: b64, contentType: "text/plain; charset=utf-8" };
}
