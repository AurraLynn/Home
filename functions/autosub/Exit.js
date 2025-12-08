/**
 * Exit.js - 统一出口（当前阶段最终占位版）
 *
 * 目标：
 *  - 让 /autosub 的“读源 + client 分流”稳定跑通
 *  - 避免你还没接完整 Parser/Renderers 就卡住入口
 *
 * 当前策略：
 *  - client = v2ray -> 返回 Base64
 *  - 其他 client -> 先明文回显（带注释）
 *
 * 你后续替换为：
 *   Parser -> Normalizer -> Router -> Renderer
 */

function toBase64Utf8(str) {
  // 兼容 CF runtime
  return btoa(unescape(encodeURIComponent(str)));
}

export function renderSubscription(rawText, { client } = {}) {
  const text = String(rawText || "").trim();

  if (!text) {
    return { body: "", contentType: "text/plain; charset=utf-8" };
  }

  const c = (client || "v2ray").toLowerCase();

  // 你要求：识别不到默认 v2ray(Base64)
  if (c === "v2ray") {
    return {
      body: toBase64Utf8(text),
      contentType: "text/plain; charset=utf-8",
    };
  }

  // 临时明文占位，方便你确认链路正确
  const banner = `# autosub passthrough (client=${c})`;
  return {
    body: [banner, text].join("\n"),
    contentType: "text/plain; charset=utf-8",
  };
}
