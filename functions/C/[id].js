// functions/C/[id].js
// 短链页面：根据 id 从 KV 中取出数据，输出带 OG meta 的 HTML + 自动跳转

export async function onRequest(context) {
  const { env, params, request } = context;
  const id = params.id;

  if (!id) {
    return new Response("Invalid id", { status: 400 });
  }

  // 从 KV 获取记录（这里用 Card_KV）
  const record = await env.Card_KV.get(id, "json");

  // 没有就说明过期或不存在
  if (!record) {
    return new Response(generateExpiredHtml(), {
      status: 404,
      headers: { "Content-Type": "text/html; charset=utf-8" },
    });
  }

  const { title, description, image, target } = record;
  const url = new URL(request.url);
  const shareUrl = `${url.origin}/C/${id}`; // 大写 C

  const html = generateShareHtml({ title, description, image, target, shareUrl });

  return new Response(html, {
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function esc(s) {
  return String(s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function generateShareHtml({ title, description, image, target, shareUrl }) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />

  <title>${esc(title)}</title>
  <meta name="description" content="${esc(description)}" />

  <!-- 微信/QQ/微博 通用 Open Graph -->
  <meta property="og:type" content="website" />
  <meta property="og:site_name" content="Lyn Share" />
  <meta property="og:title" content="${esc(title)}" />
  <meta property="og:description" content="${esc(description)}" />
  <meta property="og:image" content="${esc(image)}" />
  <meta property="og:url" content="${esc(shareUrl)}" />

  <!-- 备用 Twitter 卡片 -->
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${esc(title)}" />
  <meta name="twitter:description" content="${esc(description)}" />
  <meta name="twitter:image" content="${esc(image)}" />

  <style>
    body {
      margin: 0;
      padding: 0;
      background: #020617;
      color: #e5e7eb;
      font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      text-align: center;
    }
    .box {
      max-width: 480px;
      padding: 24px 20px;
    }
    h1 {
      font-size: 22px;
      margin-bottom: 8px;
    }
    p {
      font-size: 14px;
      margin-top: 0;
      color: #9ca3af;
    }
    .tip {
      margin-top: 16px;
      font-size: 13px;
      color: #6b7280;
    }
    a {
      color: #38bdf8;
      text-decoration: none;
    }
  </style>

  <script>
    // 给微信等抓取 meta 一点时间，再跳转到真实目标地址
    const targetUrl = ${JSON.stringify(target)};
    setTimeout(function () {
      window.location.replace(targetUrl);
    }, 800);
  </script>
</head>
<body>
  <div class="box">
    <h1>正在为你打开链接…</h1>
    <p>${esc(title)}</p>
    <p class="tip">如果长时间没有跳转，请 <a href="${esc(target)}">点击这里手动打开</a>。</p>
  </div>
</body>
</html>`;
}

function generateExpiredHtml() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>链接已失效</title>
  <style>
    body {
      margin:0;
      padding:0;
      background:#020617;
      color:#e5e7eb;
      font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
      display:flex;
      align-items:center;
      justify-content:center;
      min-height:100vh;
      text-align:center;
    }
    .box {
      max-width:360px;
      padding:24px 20px;
    }
    h1 {
      font-size:22px;
      margin-bottom:8px;
    }
    p {
      font-size:14px;
      color:#9ca3af;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>链接已失效</h1>
    <p>可能已经被删除或超过了设置的有效期。</p>
  </div>
</body>
</html>`;
}