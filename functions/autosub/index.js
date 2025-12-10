/**
 * autosub/index.js
 *
 * 作用：
 *   - 作为 Cloudflare Pages Functions 的入口
 *   - 统一处理 /autosub 请求：
 *       1. 从 KV / Query / Body 里拿到原始节点文本
 *       2. 根据 UA / query 判断目标客户端类型（clash / surge / v2ray）
 *       3. 调用 Exit.js → Parser / Normalizer / Router → 生成最终订阅内容
 *
 * 注意：
 *   - 这是 Pages Functions 写法：export async function onRequest(context)
 *   - 不是 Worker 写法（没有 export default { fetch() {} }）
 */

import { renderSubscription } from "./Exit.js";

/**
 * 获取绑定在 env 上的 Paste_Sub 命名空间
 * 方便后面做容错（未绑定时给出更清晰的报错）
 */
function getPasteKV(env) {
  return env && env.Paste_Sub ? env.Paste_Sub : null;
}

/**
 * 按 id 从 KV 中读取原始内容
 *
 * 兼容两种存储方式：
 *   1. JSON：{ content / text / data / raw / value }
 *   2. 纯文本：直接存了一段字符串
 */
async function loadFromKVById(env, id) {
  if (!id) return "";

  const kv = getPasteKV(env);
  if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

  // 1）优先尝试 JSON 读取
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

  // 2）如果不是 JSON，就当纯文本再读一次
  const rawText = await kv.get(id, "text").catch(() => "");
  if (rawText && String(rawText).trim()) return String(rawText);

  // 都没有就返回空
  return "";
}

/**
 * 根据 UA 判断大致客户端类型
 *
 * 返回：
 *   - "clash"
 *   - "surge"
 *   - "v2ray"（兜底）
 *
 * 说明：
 *   - 这里只负责「大类区分」，不区分具体哪个 Clash（Meta / Mihomo 等）
 *   - Stash 已按你的要求彻底不做特殊处理
 */
function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  // UA 为空：默认当 v2ray
  if (!ua) return "v2ray";

  // Surge（macOS / iOS）
  if (ua.includes("surge")) {
    return "surge";
  }

  // Clash 系（cfw / meta / mihomo / clash for windows 等都统一当 clash）
  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  // 其它全部当 v2ray(Base64 订阅) 处理
  return "v2ray";
}

/**
 * 决定最终 client 类型
 *
 * 优先级：
 *   1. URL 显式指定 ?client=clash|surge|v2ray
 *   2. 如果有 ?text=（调试用），默认当 clash，方便直接导入 Clash 看效果
 *   3. 其它情况按 UA 自动判断
 */
function decideClient(url, uaRaw) {
  const p = (url.searchParams.get("client") || "")
    .trim()
    .toLowerCase();

  // 显式指定优先
  if (p === "clash" || p === "surge" || p === "v2ray") {
    return p;
  }

  // 浏览器调试接口：?text= 时，强制输出 clash 配置
  if (url.searchParams.has("text")) {
    return "clash";
  }

  // 否则按 UA 判断
  return pickClientFromUA(uaRaw);
}

/**
 * Cloudflare Pages Functions 入口
 * 这里负责：
 *   - 限制路径（只响应 /autosub）
 *   - 处理 CORS 预检
 *   - 收集原始节点文本
 *   - 调用 renderSubscription 得到最终订阅内容
 */
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // 只处理 /autosub 路径，其它交给静态站
  // 如果你想改成 /api/sub，把这里的判断一起改掉
  if (path !== "/autosub") {
    return new Response("Not Found", { status: 404 });
  }

  const ua = request.headers.get("User-Agent") || "";

  // CORS 预检请求
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

  // 先决定好输出给谁用：clash / surge / v2ray
  const client = decideClient(url, ua);

  let rawText = "";
  let source = ""; // 记录数据来源：kv:id / query / body / empty，方便调试

  // ===== 1）优先从 KV 中取：?id=xxx =====
  const id = (url.searchParams.get("id") || "").trim();
  if (id) {
    rawText = await loadFromKVById(env, id).catch(() => "");
    if (rawText) {
      source = "kv:id";
    }
  }

  // ===== 2）其次从 query string 中取：?text= / ?raw= =====
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

  // ===== 3）最后从请求 body 中取（POST / PUT 等） =====
  if (!rawText && request.method !== "GET") {
    const bodyText = await request.text().catch(() => "");
    if (bodyText && String(bodyText).trim()) {
      rawText = String(bodyText);
      source = "body";
    }
  }

  // ===== 4）兜底：拿不到内容就当空文本 =====
  if (!rawText) {
    rawText = "";
    if (!source) source = "empty";
  }

  // 把 query 参数拍平为普通对象，传给 Exit.js 做更多细分控制（比如 mode / flag 等）
  const queryObj = Object.fromEntries(url.searchParams.entries());

  /**
   * renderSubscription 做的事：
   *   1. parseAnythingToNodes(rawText) → 解析各种协议/格式的节点
   *   2. normalizeNodes(nodes) → 去重 / 补充默认字段
   *   3. routeAndRender(nodes, { client, ua, query, source, rawText }) →
   *        - Clash：输出 YAML
   *        - Surge：输出 [Proxy] 段
   *        - 兜底 v2ray：输出 Base64 订阅（内置防止“二次 Base64”）
   */
  const { body, contentType } = renderSubscription(rawText, {
    client,
    source,
    ua,
    query: queryObj,
  });

  // 最终返回订阅内容
  return new Response(body || "", {
    headers: {
      "content-type": contentType || "text/plain; charset=utf-8",
      "cache-control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}
