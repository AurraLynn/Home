// functions/api/share-create.js

type StoredCard = {
  title: string;
  description: string;
  image: string;
  target: string;           // 目标内容（可能是 URL 或 文本）
  mode: "url" | "text";     // url = 跳转；text = 展示内容
  expireAt?: number | null; // 过期时间时间戳（毫秒）
  createdAt: number;
};

type Env = {
  Card_KV: KVNamespace;
};

function randomId(len = 8): string {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  let out = "";
  for (let i = 0; i < len; i++) {
    out += chars[arr[i] % chars.length];
  }
  return out;
}

function parseExpire(expire: string | undefined): number | null {
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

function normalizeTarget(raw: string): { mode: "url" | "text"; value: string } {
  const s = raw.trim();
  if (!s) {
    return { mode: "text", value: "" };
  }

  // 以 http/https 开头：直接当 URL
  if (/^https?:\/\//i.test(s)) {
    return { mode: "url", value: s };
  }

  // 看起来像域名：自动补 https://
  const looksLikeDomain = s.includes(".") && !/\s/.test(s);
  if (looksLikeDomain) {
    return { mode: "url", value: "https://" + s };
  }

  // 否则视为纯文本
  return { mode: "text", value: s };
}

export const onRequest: PagesFunction<Env> = async (context) => {
  const { request, env } = context;

  if (request.method !== "POST") {
    return new Response("Method Not Allowed", { status: 405 });
  }

  let payload: any;
  try {
    payload = await request.json();
  } catch (e) {
    return Response.json({ ok: false, message: "Invalid JSON body." }, { status: 400 });
  }

  const title = (payload.title || "").toString().trim();
  const description = (payload.description || "").toString().trim();
  const image = (payload.image || "").toString().trim();
  const targetRaw = (payload.target || "").toString();
  const expire = (payload.expire || "7d").toString();

  if (!targetRaw.trim()) {
    return Response.json({ ok: false, message: "目标内容不能为空。" }, { status: 400 });
  }

  const { mode, value: target } = normalizeTarget(targetRaw);
  const expireAt = parseExpire(expire);
  const id = randomId(8);

  const card: StoredCard = {
    title,
    description,
    image,
    target,
    mode,
    expireAt,
    createdAt: Date.now(),
  };

  await env.Card_KV.put(id, JSON.stringify(card));

  const url = new URL(request.url);
  const shareUrl = `${url.origin}/C/${id}`;

  return Response.json({ ok: true, shareUrl });
};
