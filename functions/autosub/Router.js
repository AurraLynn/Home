1import * as Clash from "./renderers/clash.js";
import * as Surge from "./renderers/surge.js";
import * as QX from "./renderers/qx.js";
import * as Stash from "./renderers/stash.js";
import * as V2Ray from "./renderers/v2ray.js";

const MAP = {
    clash: Clash,
    meta: Clash,
    mihomo: Clash,

    surge: Surge,

    qx: QX,
    quantumultx: QX,
    "quantumult-x": QX,

    stash: Stash,

    v2ray: V2Ray,
    base64: V2Ray,
};

export function routeAndRender(nodes, client, options = {}) {
    const key = (client || "v2ray").toLowerCase();
    const renderer = MAP[key] || V2Ray;
    return renderer.render(nodes, options);
}