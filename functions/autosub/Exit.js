import { parseAnythingToNodes } from "./Parser.js";
import { normalizeNodes } from "./Normalizer.js";
import { routeAndRender } from "./Router.js";

/**
 * renderSubscription: 统一出口
 * rawText -> nodes -> normalized -> renderer(client)
 */
export function renderSubscription(rawText, { client = "v2ray", query = {}, source = "" } = {}) {
  const nodes = parseAnythingToNodes(rawText);
  const normalized = normalizeNodes(nodes);

  return routeAndRender(normalized, {
    client,
    query,
    source,
    rawText,
  });
}
