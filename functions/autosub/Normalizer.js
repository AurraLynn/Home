import { isValidNode } from "./shared/utils/validate.js";

export function normalizeNodes(nodes = []) {
    const out = [];

    for (const n of nodes) {
        const node = { ...n };

        // 先给占位节点一个名字，方便你 debug 看链路
        if (!node.name) node.name = `${(node.type || "node").toUpperCase()}-AUTO`;

        // 这里只做最轻量校验（当前占位节点会大多不通过）
        if (isValidNode(node) || node.extra?.raw) {
            out.push(node);
        }
    }

    return out;
}