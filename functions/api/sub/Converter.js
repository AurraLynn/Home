// functions/api/sub/Converter.js
//
// 作用：统一的「多客户端节点转换入口」
//
// 收到 POST /api/sub/Converter?client=xxx
//   - 读取请求体中的原始节点文本（URL / Base64 / 混合都行）
//   - 根据 client 调用对应子模块（QuantumultX.js / Surge.js / Clash.js）
//   - 返回该客户端需要的订阅内容（纯文本）
//
// 说明：
//   - 这里只做「分发」，真正的解析和格式拼接都在各自的文件里完成：
//       QuantumultX.js  →  export function buildQuantumultX(bodyText) { ... }
//       Surge.js        →  export function buildSurge(bodyText) { ... }
//       Clash.js        →  export function buildClash(bodyText) { ... }   （如果你已经实现了）

import { buildQuantumultX } from "./QuantumultX.js";
import { buildSurge } from "./Surge.js";
// 如果已经有 Clash.js，并且里面导出了 buildClash，就保留；
// 如果你暂时没做 Clash 支持，可以先注释掉下面这行以及后面的分支。
import { buildClash } from "./Clash.js";

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const bodyText = await request.text();

  let out;

  try {
    if (client === "quantumultx") {
      // Quantumult X 订阅
      out = buildQuantumultX(bodyText);
    } else if (client === "surge") {
      // Surge 订阅
      out = buildSurge(bodyText);
    } else if (client === "clash" || client === "stash") {
      // Clash / Stash 订阅（如果你已经实现了 Clash.js）
      out = buildClash(bodyText);
    } else {
      // 其它客户端一律视为不支持（这里不会再继续调用）
      return new Response("unsupported client", {
        status: 400,
        headers: { "content-type": "text/plain; charset=utf-8" },
      });
    }
  } catch (e) {
    // 任何 JS 运行异常，统一包装成 convert error，避免直接 1101
    const msg =
      e && typeof e === "object" && "message" in e
        ? e.message
        : String(e || "unknown error");
    return new Response("convert error: " + msg, {
      status: 500,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // 正常返回客户端订阅内容
  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}