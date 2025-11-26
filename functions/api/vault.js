// functions/api/vault.js
// 路由：/api/vault

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const { pathname } = url;

  // 简单 CORS（其实同源访问不写也行，写上不影响）
  const corsHeaders = {
    "Access-Control-Allow-Origin": request.headers.get("Origin") || "*",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };

  // 预检
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (pathname !== "/api/vault") {
    return new Response("Not found", { status: 404, headers: corsHeaders });
  }

  // GET：读取密文
  if (request.method === "GET") {
    const raw = await env.VAULT.get("vault-data");
    if (!raw) {
      // 第一次使用：还没有任何数据
      return new Response(
        JSON.stringify({ exists: false }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders,
          },
        }
      );
    }

    // raw 是之前存的 JSON 字符串：{ salt, iv, ciphertext }
    return new Response(
      JSON.stringify({ exists: true, ...JSON.parse(raw) }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  // POST：保存密文
  if (request.method === "POST") {
    const bodyText = await request.text();

    try {
      const parsed = JSON.parse(bodyText);
      if (!parsed || !parsed.salt || !parsed.iv || !parsed.ciphertext) {
        return new Response(
          JSON.stringify({ ok: false, error: "Invalid payload" }),
          {
            status: 400,
            headers: {
              "Content-Type": "application/json",
              ...corsHeaders,
            },
          }
        );
      }
    } catch (e) {
      return new Response(
        JSON.stringify({ ok: false, error: "Invalid JSON" }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            ...corsHeaders,
          },
        }
      );
    }

    await env.VAULT.put("vault-data", bodyText);

    return new Response(
      JSON.stringify({ ok: true }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          ...corsHeaders,
        },
      }
    );
  }

  return new Response("Method not allowed", { status: 405, headers: corsHeaders });
}