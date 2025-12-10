/* index.js
 * ============================================
 * ⚠️ 注意：这里是 Cloudflare Pages Functions 写法
 * ============================================
 *
 * 1. 当前项目使用的是「Pages + Functions」，不是「独立 Workers」。
 *
 *    - ✅ 正确写法（Pages Functions）：
 *        export async function onRequest(context) { ... }
 *
 *    - ❌ 错误写法（Workers）：
 *        export default {
 *          async fetch(request, env, ctx) { ... }
 *        }
 *
 * 2. 如果误用 Workers 写法：
 *    - Pages 不会把 /autosub 交给这个文件处理；
 *    - 路由未命中 → 会回到静态站首页，看起来像「接口失效/路由不通」。
 *
 * 3. 路由规则：
 *    - 目录：functions/autosub/index.js
 *    - 路径：https://你的域名/autosub
 *
 * 4. 入口说明：
 *    - 这里接收请求，解析 URL / UA；
 *    - 从 KV(Paste_Sub) / ?text= / body 中取原始节点文本；
 *    - 决定 client 类型（clash/surge/v2ray）；
 *    - 调用 Exit.js 完成解析 + 转换后返回。
 */

import { renderSubscription } from "./Exit.js";
import { pickClientFromUA } from "./Router.js";

/* 获取绑定的 KV 命名空间（Paste_Sub）
 * ------------------------------------------------
 * 在 wrangler/Pages 项目中，需要在配置里绑定：
 *   kv_namespaces:
 *     - binding: Paste_Sub
 *       id: xxxx
 *
 * 若未绑定，调用时会抛错，方便在调试阶段发现问题。
 */
function getPasteKV(env) {
  return env && env.Paste_Sub ? env.Paste_Sub : null;
}

/* 从 KV 里按 id 读取原始文本
 * ------------------------------------------------
 * 支持两种存储形式：
 *   1) JSON：{ content / text / data / raw / value }
 *   2) 纯文本：直接 get(id, "text")
 */
async function loadFromKVById(env, id) {
  if (!id) return "";

  const kv = getPasteKV(env);
  if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

  const rec = await kv.get(id, "json").catch(() => null);
  if (rec && typeof rec === "object") {
    const raw =
      rec.content ||
      rec.text ||
      rec.data ||
      rec.raw ||
      rec.value ||
      "";
    return raw && String(raw).trim() ? String(raw) : "";
  }

  const rawText = await kv.get(id, "text").catch(() => "");
  return rawText && String(rawText).trim() ? String(rawText) : "";
}

/* 选择 client 类型
 * ------------------------------------------------
 * 优先级：
 *   1) URL 上显式指定 ?client=clash/surge/v2ray
 *   2) 未指定 client，但存在 ?text=xxx → 视为调试用，固定输出 Clash
 *   3) 其它情况：根据 UA 猜测（Clash/Stash/Surge），识别失败 → v2ray(Base64)
 *
 * 特别说明：
 *   - ?text= 用作调试入口：
 *       https://域名/autosub?text=节点文本
 *     无需指定 client，默认直接返回 Clash 的 proxies 订阅，方便浏览器调试。
 */
function pickClient(url, ua) {
  const p = (url.searchParams.get("client") || "").trim().toLowerCase();

  /* 1) 显式指定 client */
  if (p === "clash" || p === "surge" || p === "v2ray") {
    return p;
  }

  /* 2) ?text= 调试模式：固定当 Clash 使用 */
  if (url.searchParams.has("text")) {
    return "clash";
  }

  /* 3) 其余走 UA 识别逻辑（Router.js 中实现），失败兜底 v2ray */
  return pickClientFromUA(ua);
}

/* Pages Functions 入口：
 * ------------------------------------------------
 * ⚠️ 这里必须导出 onRequest（或 onRequestGet/onRequestPost 等），
 *    否则 Pages 不会调用这个文件，/autosub 路由会直接回到静态页面。
 *
 * context 对象包含：
 *   - request：原始 Request
 *   - env：绑定的 KV / 环境变量
 *   - params：动态路由参数（当前未使用）
 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const ua = request.headers.get("User-Agent") || "";

  const client = pickClient(url, ua);

  let rawText = "";
  let source = "";

  /* 1) 优先：从 KV 里按 id 拉取
   *   - 使用场景：前端先把内容存到 Paste_Sub，再用 id 生成订阅链接。
   *   - 示例：/autosub?id=xxxx&client=clash
   */
  const id = (url.searchParams.get("id") || "").trim();
  if (id) {
    rawText = await loadFromKVById(env, id).catch(() => "");
    if (rawText) {
      source = "kv:id";
    }
  }

  /* 2) 其次：query 直接带文本 ?text= / ?raw=
   *   - 使用场景：浏览器调试、简单测试。
   *   - 示例：/autosub?text=vmess://xxxxx
   */
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

  /* 3) 再次：POST / PUT 请求 body 里发原始文本
   *   - 使用场景：脚本 / 后端服务通过 curl/fetch 直接 POST 一坨节点文本。
   *   - 示例：
   *       curl -X POST "https://域名/autosub?client=clash" --data-binary $'vmess://...\nvless://...'
   */
  if (!rawText && request.method !== "GET") {
    const bodyText = await request.text().catch(() => "");
    if (bodyText && String(bodyText).trim()) {
      rawText = String(bodyText);
      source = "body";
    }
  }

  /* 4) 兜底：完全没有任何内容时，rawText 为空串
   *   - renderSubscription 内部会正常处理（返回空配置 / 统计信息）。
   */
  if (!rawText) {
    rawText = "";
    source = source || "empty";
  }

  const { body, contentType } = renderSubscription(rawText, {
    client,
    source,
    ua,
    query: Object.fromEntries(url.searchParams.entries()),
  });

  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}