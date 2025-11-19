const KV_KEY = "history";
const MAX_HISTORY = 100;

// Cloudflare Pages Functions 入口
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  // ✅ 这里做一个自检：HOME 有没有绑上
  if (!env.HOME || typeof env.HOME.get !== "function") {
    return new Response(
      'KV binding "HOME" is not configured. 请在 Pages 的 KV 绑定里把命名空间 Home 绑定为变量名 HOME。',
      { status: 500, headers: corsHeaders }
    );
  }

  // 预检请求（CORS）
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  // 只处理 /api/history
  if (url.pathname === "/api/history") {
    if (request.method === "GET") {
      return handleGetHistory(env, corsHeaders);
    }
    if (request.method === "POST") {
      return handlePostHistory(request, env, corsHeaders);
    }
    return new Response("Method Not Allowed", {
      status: 405,
      headers: corsHeaders,
    });
  }

  return new Response("Not Found", {
    status: 404,
    headers: corsHeaders,
  });
}

async function handleGetHistory(env, corsHeaders) {
  const data = await env.HOME.get(KV_KEY, { type: "json" });
  const history = Array.isArray(data) ? data : [];

  return new Response(JSON.stringify(history), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      ...corsHeaders,
    },
  });
}

async function handlePostHistory(request, env, corsHeaders) {
  try {
    const body = await request.json();
    const { content, author, likeCount = 0, isUserComment = false } = body;

    if (!content || !author) {
      return new Response("content & author required", {
        status: 400,
        headers: corsHeaders,
      });
    }

    const now = new Date();
    const data = await env.HOME.get(KV_KEY, { type: "json" });
    const history = Array.isArray(data) ? data : [];

    const newItem = {
      id: Date.now(),
      content, // 鸡汤内容
      author,  // 作者，比如：甄姬（宫里传出来的）
      timestamp: now.toLocaleString("zh-CN", { hour12: false }),
      liked: false,
      likeCount,
      isUserComment,
      avatarIndex: Math.floor(Math.random() * 41) + 1, // tx1~tx41
    };

    history.unshift(newItem);
    const trimmed = history.slice(0, MAX_HISTORY);

    await env.HOME.put(KV_KEY, JSON.stringify(trimmed));

    return new Response(JSON.stringify(newItem), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        ...corsHeaders,
      },
    });
  } catch (e) {
    return new Response("bad request", {
      status: 400,
      headers: corsHeaders,
    });
  }
}
