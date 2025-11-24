// src/index.js

// 映射 TTL key 到秒数
const TTL_MAP = {
  "10m": 10 * 60,
  "1d": 24 * 60 * 60,
  "7d": 7 * 24 * 60 * 60,
  "30d": 30 * 24 * 60 * 60,
  "forever": 0,
};

// 简单生成 8 位 ID
function generateId() {
  const bytes = new Uint8Array(4);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// 文件名 -> 路径 slug
function slugify(name) {
  const s = name
    .trim()
    .toLowerCase()
    .replace(/\s+/g, "-")
    .replace(/[^a-z0-9\-]/g, "");
  return s || null;
}

// 统一 JSON 返回
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

// 计算过期时间 & KV 选项
function buildExpiry(ttlKey) {
  const seconds = TTL_MAP[ttlKey] ?? TTL_MAP["10m"];
  const now = Date.now();
  if (seconds > 0) {
    return {
      expiresAt: now + seconds * 1000,
      kvOptions: { expirationTtl: seconds },
    };
  }
  return {
    expiresAt: null,
    kvOptions: {},
  };
}

async function handlePost(request, env) {
  const url = new URL(request.url);
  const baseUrl = url.origin + "/Paste";

  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ ok: false, error: "请求体必须是 JSON" }, 400);
  }

  const action = body.action;
  if (!action) {
    return jsonResponse({ ok: false, error: "缺少 action 字段" }, 400);
  }

  // 通用字段
  const rawSlug = (body.slug || "").toString().trim() || null;
  const filename = (body.filename || "").toString().trim() || "";
  const content = (body.content || "").toString();
  const ttlKey = (body.ttlKey || "10m").toString();
  const managePassword = (body.managePassword || "").toString();

  // === 创建 ===
  if (action === "create") {
    if (!content.trim()) {
      return jsonResponse({ ok: false, error: "内容不能为空" }, 400);
    }

    let slug = null;
    let mode = "temp";
    let hasPassword = false;

    if (managePassword) {
      mode = "managed";
      hasPassword = true;
    }

    // 有管理密码且有文件名 => 尝试用文件名作为 slug
    if (managePassword && filename) {
      const s = slugify(filename);
      if (!s) {
        return jsonResponse({ ok: false, error: "文件名格式不合法" }, 400);
      }
      // 检查是否已存在
      const existing = await env.PASTE.get(s);
      if (existing) {
        return jsonResponse({ ok: false, error: "该文件名路径已被占用，请换一个" }, 409);
      }
      slug = s;
    } else {
      // 临时分享或无文件名 => 用随机 ID
      slug = generateId();
    }

    const { expiresAt, kvOptions } = buildExpiry(ttlKey);

    const now = Date.now();
    const record = {
      slug,
      filename: filename || null,
      content,
      createdAt: now,
      updatedAt: now,
      ttlKey,
      expiresAt,
      mode,
      hasPassword,
      password: hasPassword ? managePassword : null,
    };

    await env.PASTE.put(slug, JSON.stringify(record), kvOptions);

    const viewUrl = `${baseUrl}?id=${encodeURIComponent(slug)}`;
    const plain = content.replace(/\s+/g, " ").trim();
    const snippet = plain.length > 40 ? plain.slice(0, 40) + "…" : plain || "（无内容）";
    const shareText = `${baseUrl}/${filename || slug} ${snippet}`;

    return jsonResponse({
      ok: true,
      action: "create",
      slug,
      filename: record.filename,
      content: record.content,
      ttlKey: record.ttlKey,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      mode: record.mode,
      hasPassword: record.hasPassword,
      viewUrl,
      shareText,
    }, 201);
  }

  // === 更新 ===
  if (action === "update") {
    if (!rawSlug) {
      return jsonResponse({ ok: false, error: "缺少 slug" }, 400);
    }
    if (!content.trim()) {
      return jsonResponse({ ok: false, error: "内容不能为空" }, 400);
    }

    const val = await env.PASTE.get(rawSlug);
    if (!val) {
      return jsonResponse({ ok: false, error: "内容不存在或已过期" }, 404);
    }
    let record;
    try {
      record = JSON.parse(val);
    } catch {
      return jsonResponse({ ok: false, error: "存储格式错误，无法更新" }, 500);
    }

    if (!record.hasPassword) {
      return jsonResponse({ ok: false, error: "该内容未设置管理密码，不支持更新" }, 403);
    }
    if (!managePassword) {
      return jsonResponse({ ok: false, error: "更新时必须提供管理密码" }, 400);
    }
    if (record.password !== managePassword) {
      return jsonResponse({ ok: false, error: "管理密码不正确" }, 403);
    }

    const { expiresAt, kvOptions } = buildExpiry(ttlKey);

    record.content = content;
    record.ttlKey = ttlKey;
    record.expiresAt = expiresAt;
    record.updatedAt = Date.now();
    // 文件名如果有新值，也允许改
    record.filename = filename || record.filename || null;

    await env.PASTE.put(rawSlug, JSON.stringify(record), kvOptions);

    const viewUrl = `${baseUrl}?id=${encodeURIComponent(record.slug)}`;
    const plain = content.replace(/\s+/g, " ").trim();
    const snippet = plain.length > 40 ? plain.slice(0, 40) + "…" : plain || "（无内容）";
    const shareText = `${baseUrl}/${record.filename || record.slug} ${snippet}`;

    return jsonResponse({
      ok: true,
      action: "update",
      slug: record.slug,
      filename: record.filename,
      content: record.content,
      ttlKey: record.ttlKey,
      createdAt: record.createdAt,
      expiresAt: record.expiresAt,
      mode: record.mode,
      hasPassword: record.hasPassword,
      viewUrl,
      shareText,
    });
  }

  // === 删除 ===
  if (action === "delete") {
    if (!rawSlug) {
      return jsonResponse({ ok: false, error: "缺少 slug" }, 400);
    }
    const val = await env.PASTE.get(rawSlug);
    if (!val) {
      return jsonResponse({ ok: false, error: "内容不存在或已过期" }, 404);
    }
    let record;
    try {
      record = JSON.parse(val);
    } catch {
      return jsonResponse({ ok: false, error: "存储格式错误，无法删除" }, 500);
    }

    if (!record.hasPassword) {
      return jsonResponse({ ok: false, error: "该内容未设置管理密码，不支持删除" }, 403);
    }
    if (!managePassword) {
      return jsonResponse({ ok: false, error: "删除时必须提供管理密码" }, 400);
    }
    if (record.password !== managePassword) {
      return jsonResponse({ ok: false, error: "管理密码不正确" }, 403);
    }

    await env.PASTE.delete(rawSlug);
    return jsonResponse({ ok: true, action: "delete", deleted: true });
  }

  return jsonResponse({ ok: false, error: "不支持的 action" }, 400);
}

async function handleGet(request, env) {
  const url = new URL(request.url);
  const path = url.pathname; // /api/paste 或 /api/paste/{slug}

  if (!path.startsWith("/api/paste")) {
    return jsonResponse({ ok: false, error: "Not Found" }, 404);
  }

  if (path === "/api/paste") {
    return jsonResponse({ ok: false, error: "缺少 ID" }, 400);
  }

  const slug = path.replace("/api/paste/", "");
  if (!slug) {
    return jsonResponse({ ok: false, error: "缺少 ID" }, 400);
  }

  const val = await env.PASTE.get(slug);
  if (!val) {
    return jsonResponse({ ok: false, error: "内容不存在或已过期" }, 404);
  }

  let record;
  try {
    record = JSON.parse(val);
  } catch {
    return jsonResponse({ ok: false, error: "存储格式错误" }, 500);
  }

  return jsonResponse({
    ok: true,
    slug: record.slug,
    filename: record.filename,
    content: record.content,
    ttlKey: record.ttlKey,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    expiresAt: record.expiresAt,
    mode: record.mode,
    hasPassword: record.hasPassword,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/paste" || url.pathname.startsWith("/api/paste/")) {
      if (request.method === "POST") {
        return handlePost(request, env);
      }
      if (request.method === "GET") {
        return handleGet(request, env);
      }
      return jsonResponse({ ok: false, error: "Method Not Allowed" }, 405);
    }

    return new Response("Not Found", { status: 404 });
  },
};