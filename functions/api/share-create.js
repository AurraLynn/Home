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

function parseExpire(expire) {
  const now = Date.now();
  switch (expire) {
    case "1d":
      return now + 1 * 24 * 60 * 60 * 1000;
    case "7d":
      return now + 7 * 24 * 60 * 60 * 1000;
    case "30d":
      return now + 30 * 24 * 60 * 60 * 1000;
    case "forever":
    default:
      return null;
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
  const expire = (payload.expire || "7d").toString();

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
  const expireAt = parseExpire(expire);

  const id = randomId(8);
  const card = {
    title,
    description,
    image,
    target,
    mode,
    expireAt,
    createdAt: Date.now()
  };

  await env.Card_KV.put(id, JSON.stringify(card));

  const url = new URL(request.url);
  const shareUrl = `${url.origin}/C/${id}`;

  return new Response(
    JSON.stringify({ ok: true, shareUrl }),
    { headers: { "Content-Type": "application/json" } }
  );
}
