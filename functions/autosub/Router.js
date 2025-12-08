import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";
import { renderQX } from "./renderers/qx.js";

function toB64(text) {
    const t = String(text || "").trim();
    return btoa(unescape(encodeURIComponent(t)));
}

export function routeAndRender(nodes, { client = "v2ray", rawText = "" } = {}) {
    const c = String(client || "v2ray").toLowerCase();

    if (c === "clash") return renderClash(nodes);
    if (c === "surge") return renderSurge(nodes);
    if (c === "qx") return renderQX(nodes);

    // 你原规则：识别不到默认 v2ray(Base64)
    return {
        body: toB64(rawText),
        contentType: "text/plain; charset=utf-8",
    };
}