// functions/api/history.js

const KV_KEY = "history";   // KV 里使用的键名
const MAX_HISTORY = 100;    // 最多保留 100 条记录

// Cloudflare Pages Functions 入口
export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  // 处理预检请求（CORS）
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

// 读取历史记录
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

// 写入历史记录（插入一条，最多保留 100 条）
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

    // 从 KV 取出当前数组
    const data = await env.HOME.get(KV_KEY, { type: "json" });
    const history = Array.isArray(data) ? data : [];

    const newItem = {
      id: Date.now(),
      content,                          // 鸡汤内容
      author,                           // 作者字符串，例如：甄姬（宫里传出来的）
      timestamp: now.toLocaleString("zh-CN", { hour12: false }),
      liked: false,
      likeCount,
      isUserComment,
      // 1~41 的随机头像编号，对应 tx1.jpg ~ tx41.jpg
      avatarIndex: Math.floor(Math.random() * 41) + 1,
    };

    // 新记录插到最前面
    history.unshift(newItem);

    // 最多保留 100 条
    const trimmed = history.slice(0, MAX_HISTORY);

    // 写回 KV
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