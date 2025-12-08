import { parseAnythingToNodes } from "./Parser.js";
import { normalizeNodes } from "./Normalizer.js";
import { routeAndRender } from "./Router.js";

export function renderSubscription(rawText, options = {}) {
    const client = (options.client || "v2ray").toLowerCase();
    const renderOptions = options.renderOptions || {};

    const nodes = parseAnythingToNodes(rawText);
    const normalized = normalizeNodes(nodes);

    const body = routeAndRender(normalized, client, renderOptions);

    const contentType =
        client === "clash" || client === "meta" || client === "mihomo" || client === "stash"
            ? "text/yaml; charset=utf-8"
            : "text/plain; charset=utf-8";

    return {
        body,
        contentType,
        nodesCount: normalized.length,
    };
}