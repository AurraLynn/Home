// functions/api/sub/Converter.js
//
// 作用：
//  - 接收原始文本（可能是 Base64 / URL / 混合，单条或多条）
//  - 根据 ?client= 决定输出格式：
//      quantumultx → 调用 QuantumultX.js
//      surge       → 调用 Surge.js
//      clash       → 调用 Clash.js
//      其它 / 空   → 输出 Base64 订阅（v2ray / 小火箭 等吃 Base64 的客户端）
//
// 支持输入：
//  - URL 格式
//  - URL / Base64 混合格式
//  - Base64（单条或多条）
//
// 支持输出：
//  - Quantumult X 配置片段（shadowsocks / trojan / vmess / vless / hy2 ...）
//  - Surge [Proxy] 行（shadowsocks / trojan / vmess / hy2 ...）
//  - Clash proxies 段（shadowsocks / trojan / vmess / vless / hy / hy2 ...）
//  - Base64 订阅（未识别 client 时）
//
// 已支持的客户端：
//  - Quantumult X
//  - Surge / Surfboard
//  - Clash / Clash.Meta / Mihomo / FlyClash
//  - 食用 Base64 的客户端（Shadowrocket / v2rayNG / Sing-box 等）

import { buildQuantumultX } from "./QuantumultX.js";
import { buildSurge } from "./Surge.js";
import { buildClash } from "./Clash.js";

export async function onRequestPost(context) {
  const { request } = context;
  const url = new URL(request.url);
  const client = (url.searchParams.get("client") || "").toLowerCase();

  const raw = await request.text();
  if (!raw || !raw.trim()) {
    return new Response("empty body", {
      status: 400,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  let outText = "";

  if (client === "quantumultx") {
    outText = buildQuantumultX(raw);
  } else if (client === "surge") {
    outText = buildSurge(raw);
  } else if (client === "clash") {
    outText = buildClash(raw);
  } else {
    // 默认：返回 Base64 订阅，适配 Shadowrocket / v2rayNG 等
    outText = toBase64Utf8(raw);
  }

  return new Response(outText, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}

/* ========== UTF-8 → Base64 ========== */

function toBase64Utf8(str) {
  // 处理 emoji / 中文
  const utf8 = encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (m, p1) =>
    String.fromCharCode(parseInt(p1, 16))
  );
  return btoa(utf8);
}
