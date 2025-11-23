// functions/api/share-create.js
// 接收前端传的标题/描述/图片/目标链接/过期时间，写入 KV，返回短链 /C/:id

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    const body = await request.json();
    const { title, description, image, target, expire } = body || {};

    if (!title || !description || !image || !target) {
      return json(
        { ok: false, message: "请填写完整：标题、描述、图片地址、目标链接" },
        { status: 400 }
      );
    }

    // 生成短 ID
    const id = generateId();

    // 过期时间：秒
    const expireMap = {
      "1d": 60 * 60 * 24,
      "7d": 60 * 60 * 24 * 7,
      "30d": 60 * 60 * 24 * 30,
      forever: null,
    };
    const ttl = expireMap[expire] ?? expireMap["7d"];

    const data = {
      title,
      description,
      image,
      target,
      createdAt: Date.now(),
      expire,
    };

    // 写入 KV（用 Card_KV）
    if (ttl) {
      await env.Card_KV.put(id, JSON.stringify(data), { expirationTtl: ttl });
    } else {
      await env.Card_KV.put(id, JSON.stringify(data));
    }

    const url = new URL(request.url);
    // 短链前缀：/C/（大写 C）
    const shareUrl = `${url.origin}/C/${id}`;

    return json({ ok: true, id, shareUrl });
  } catch (e) {
    return json(
      { ok: false, message: "服务异常，请稍后重试" },
      { status: 500 }
    );
  }
}

function generateId() {
  const chars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let id = "";
  for (let i = 0; i < 6; i++) {
    id += chars[Math.floor(Math.random() * chars.length)];
  }
  return id;
}

// 小工具：返回 JSON
function json(data, init = {}) {
  const headers = new Headers(init.headers || {});
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(data), {
    ...init,
    headers,
  });
}