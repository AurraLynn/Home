// functions/api/share-create.js

// KV 里存的结构：title/description/image/target/mode/expireAt/createdAt
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

function normalizeTarget(raw) {
  const s = (raw || "").trim();
  if (!s) {
    return { mode: "text", value: "" };
  }

  // 以 http/https 开头：直接当 URL
  if (/^https?:\/\//i.test(s)) {
    return { mode: "url", value: s };
  }

  // 看起来像域名：自动加 https://
  const looksLikeDomain = s.includes(".") && !/\s/.test(s);
  if (looksLikeDomain) {
    return { mode: "url", value: "https://" + s };
  }

  // 否则当文本
  return { mode: "text", value: s };
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
      JSON.stringify({ ok: false, message: "目标内容不能为空。" }),
      { status: 400, headers: { "Content-Type": "application/json" } }
    );
  }

  const norm = normalizeTarget(targetRaw);
  const target = norm.value;
  const mode = norm.mode;
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
