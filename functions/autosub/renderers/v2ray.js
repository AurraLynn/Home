import { safeB64Encode } from "../shared/utils/base64.js";

export function render(nodes) {
    // 先把原始行拼回去做默认订阅（骨架策略）
    const lines = nodes.map((n) => n.extra?.raw).filter(Boolean);
    const text = lines.join("\n");
    return safeB64Encode(text);
}1