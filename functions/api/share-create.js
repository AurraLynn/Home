// functions/api/share-create.js

function randomId(len = 8) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[arr[i] % chars.length];
  }
  return out;
}

/**
 * 解析前端传来的 expire 选项：
 *   - "1d"  → 1 天
 *   - "7d"  → 7 天
 *   - "30d" → 30 天
 *   - "forever" / 其它 → 永不过期
 *
 * 返回：
 *   {
 *     expireAt: 毫秒时间戳 或 null,
 *     ttlSeconds: 秒数 或 null （用于 KV 的 expirationTtl）
 *   }
 */
function parseExpire(expire) {
  const now = Date.now();

  switch (expire) {
    case "1d": {
      const ms = 1 * 24 * 60 * 60 * 1000;
      return { expireAt: now + ms, ttlSeconds: ms / 1000 };
    }
    case "7d": {
      const ms = 7 * 24 * 60 * 60 * 1000;
      return { expireAt: now + ms, ttlSeconds: ms / 1000 };
    }
    case "30d": {
      const ms = 30 * 24 * 60 * 60 * 1000;
      return { expireAt: now + ms, ttlSeconds: ms / 1000 };
    }
    case "forever":
    default:
      // 永不过期：不设置 expireAt / expirationTtl
      return { expireAt: null, ttlSeconds: null };
  }
}

// 只接受链接：
// - 任意 scheme://
// - 或类似 baidu.com 这种域名形式（自动补 https://）
// 其它一律报错
function normalizeTarget(raw) {
  const s = (raw || "").trim();
  if (!s) {
    return { ok: false, message: "目标链接不能为空。" };
  }

  // 任意协议：http://, https://, shadowrocket://, clash:// 等
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(s)) {
    return { ok: true, mode: "url", value: s };
  }

  // 看起来像域名：自动加 https://
  const looksLikeDomain = s.includes(".") && !/\s/.test(s);
  if (looksLikeDomain) {
    return { ok: true, mode: "url", value: "https://" + s };
  }

  // 其它情况视为非法
  return { ok: false, message: "目标必须是合法链接，不支持纯文本内容。" };
}

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let payload;
  try {
    payload = await request.json();
  } catch (e) {
    return new Response(
      JSON.stringify({ ok: false, message: "Invalid JSON body." }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const title = (payload.title || "").toString().trim();
  const description = (payload.description || "").toString().trim();
  const image = (payload.image || "").toString().trim();
  const targetRaw = (payload.target || "").toString();
  const expire = (payload.expire || "7d").toString(); // "1d" | "7d" | "30d" | "forever"

  if (!targetRaw.trim()) {
    return new Response(
      JSON.stringify({ ok: false, message: "目标链接不能为空。" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const norm = normalizeTarget(targetRaw);
  if (!norm.ok) {
    return new Response(
      JSON.stringify({ ok: false, message: norm.message }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const target = norm.value;
  const mode = "url"; // 现在只允许链接

  // 解析有效期：得到 expireAt（给自己用）+ ttlSeconds（给 KV 用）
  const { expireAt, ttlSeconds } = parseExpire(expire);

  const id = randomId(8);
  const now = Date.now();

  const card = {
    title,
    description,
    image,
    target,
    mode,
    expireAt,      // 逻辑过期时间（毫秒），给 /C/[id].js 用来判断 & 懒删除
    createdAt: now
  };

  // KV 写入选项：如果有 ttlSeconds，就设置 expirationTtl
  const kvOptions = {};
  if (ttlSeconds && Number.isFinite(ttlSeconds) && ttlSeconds > 0) {
    kvOptions.expirationTtl = ttlSeconds; // 单位：秒
  }

  await env.Card_KV.put(id, JSON.stringify(card), kvOptions);

  const url = new URL(request.url);
  const shareUrl = `${url.origin}/C/${id}`;

  return new Response(
    JSON.stringify({ ok: true, shareUrl }),
    { headers: { "Content-Type": "application/json" } }
  );
}
