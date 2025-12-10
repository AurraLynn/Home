/* index.js
 * 文件作用：
 *   - 作为 Cloudflare Pages Functions 入口
 *   - 接收请求 → 获取节点文本 → 判断客户端类型 → 调用 Exit.js 生成订阅内容
 *
 * 注意：
 *   - 这里是 Pages Functions 写法：export async function onRequest(context)
 *   - 不能用 Workers 写法：export default { async fetch(request, env, ctx) { ... } }
 */

import { renderSubscription } from "./Exit.js";

/* 从 env 中拿到 Paste_Sub 这个 KV */
function getPasteKV(env) {
  return env && env.Paste_Sub ? env.Paste_Sub : null;
}

/* 按 id 从 KV 里面读原始文本 */
async function loadFromKVById(env, id) {
  if (!id) return "";

  const kv = getPasteKV(env);
  if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

  // 优先尝试 JSON
  const rec = await kv.get(id, "json").catch(() => null);
  if (rec && typeof rec === "object") {
    const raw =
      rec.content ||
      rec.text ||
      rec.data ||
      rec.raw ||
      rec.value ||
      "";
    if (raw && String(raw).trim()) return String(raw);
  }

  // 其次尝试纯文本
  const rawText = await kv.get(id, "text").catch(() => "");
  if (rawText && String(rawText).trim()) return String(rawText);

  return "";
}

/* 根据 UA 判断客户端类型
 * 返回："clash" / "surge" / "v2ray"
 */
function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  // UA 为空：兜底 v2ray
  if (!ua) return "v2ray";

  // Surge
  if (ua.includes("surge")) {
    return "surge";
  }

  // Clash 系（clash / meta / mihomo / cfw / clash for windows）
  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  // 其他全部当 v2ray(Base64)
  return "v2ray";
}

/* 决定最终使用的 client 类型
 * 优先级：
 *   1. URL 上显式 ?client=clash/surge/v2ray
 *   2. ?text= 存在时，固定当 clash（方便浏览器调试）
 *   3. 其余情况按 UA 判断
 */
function decideClient(url, uaRaw) {
  const p = (url.searchParams.get("client") || "")
    .trim()
    .toLowerCase();

  if (p === "clash" || p === "surge" || p === "v2ray") {
    return p;
  }

  // 调试接口：?text= 直接当 Clash 使用
  if (url.searchParams.has("text")) {
    return "clash";
  }

  return pickClientFromUA(uaRaw);
}

/* 入口函数：处理所有 /autosub 请求 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // 只处理 /autosub 路径，其它路径交给静态页面
  if (path !== "/autosub") {
    return new Response("Not Found", { status: 404 });
  }

  const ua = request.headers.get("User-Agent") || "";

  // CORS 预检
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Credentials": "true",
      },
    });
  }

  // 决定客户端类型：clash / surge / v2ray
  const client = decideClient(url, ua);

  let rawText = "";
  let source = "";

  // 1) 优先从 KV:id 读
  const id = (url.searchParams.get("id") || "").trim();
  if (id) {
    rawText = await loadFromKVById(env, id).catch(() => "");
    if (rawText) {
      source = "kv:id";
    }
  }

  // 2) 其次从 query text/raw 取
  if (!rawText) {
    const qText =
      url.searchParams.get("text") ||
      url.searchParams.get("raw") ||
      "";
    if (qText && String(qText).trim()) {
      rawText = String(qText);
      source = "query";
    }
  }

  // 3) 再次从 body 取（POST/PUT）
  if (!rawText && request.method !== "GET") {
    const bodyText = await request.text().catch(() => "");
    if (bodyText && String(bodyText).trim()) {
      rawText = String(bodyText);
      source = "body";
    }
  }

  // 4) 兜底：没有内容就是空串
  if (!rawText) {
    rawText = "";
    if (!source) source = "empty";
  }

  // 把 query 转成普通对象，方便 Exit.js 使用
  const queryObj = Object.fromEntries(url.searchParams.entries());

  // 交给 Exit.js 处理：
  //   - 解析节点（ss/vmess/vless/trojan/hy2 等）
  //   - 规范化
  //   - 调用 Router.routeAndRender，输出 Clash/Surge/v2ray 格式
  const { body, contentType } = renderSubscription(rawText, {
    client,
    source,
    ua,
    query: queryObj,
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}