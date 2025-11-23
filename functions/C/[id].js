// functions/C/[id].js

function escapeHtml(str) {
  if (!str) return "";
  return String(str).replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case "&": return "&amp;";
      case "<": return "&lt;";
      case ">": return "&gt;";
      case '"': return "&quot;";
      case "'": return "&#39;";
      default: return ch;
    }
  });
}

function renderPage(options) {
  const card = options.card || null;
  const url = options.url;
  const expired = !!options.expired;

  const title = card && card.title ? card.title : "Lyn's Card";
  const desc = card && card.description
    ? card.description
    : (expired ? "This link has expired." : "A card shared by Lyn.");
  const image = card && card.image
    ? card.image
    : "https://save.aura.us.kg/Picture/Preview/YL1.png";

  const isTextMode = card && card.mode === "text";

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)}</title>

  <!-- OG / WeChat / QQ 预览 -->
  <meta property="og:type" content="website">
  <meta property="og:title" content="${escapeHtml(title)}">
  <meta property="og:description" content="${escapeHtml(desc)}">
  <meta property="og:image" content="${escapeHtml(image)}">
  <meta property="og:url" content="${escapeHtml(url)}">

  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #020617;
      color: #f9fafb;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 16px;
    }
    .shell {
      width: 100%;
      max-width: 480px;
    }
    .card {
      background: radial-gradient(circle at top, #020617, #020617);
      border-radius: 24px;
      padding: 24px 20px 20px;
      border: 1px solid rgba(148, 163, 184, 0.4);
      box-shadow:
        0 24px 60px rgba(15, 23, 42, 0.9),
        0 0 0 1px rgba(15, 23, 42, 0.6);
    }
    .title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
      text-align: center;
    }
    .subtitle {
      font-size: 13px;
      color: #9ca3af;
      text-align: center;
      margin-bottom: 18px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid rgba(148, 163, 184, 0.5);
      background: rgba(15, 23, 42, 0.8);
      font-size: 11px;
      color: #e5e7eb;
      margin: 0 auto 18px;
    }
    .badge-dot {
      width: 7px;
      height: 7px;
      border-radius: 999px;
      background: #22c55e;
      box-shadow: 0 0 8px rgba(34, 197, 94, 0.9);
    }
    .info {
      font-size: 12px;
      color: #9ca3af;
      text-align: center;
      margin-bottom: 16px;
      min-height: 32px;
    }
    .countdown {
      font-size: 12px;
      text-align: center;
      margin-bottom: 16px;
      color: #e5e7eb;
    }
    .countdown strong {
      font-size: 16px;
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: center;
      margin-bottom: 12px;
    }
    .btn {
      padding: 8px 14px;
      border-radius: 999px;
      border: none;
      font-size: 13px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-primary {
      background: #facc15;
      color: #1f2937;
    }
    .btn-secondary {
      background: rgba(15, 23, 42, 0.9);
      color: #e5e7eb;
      border: 1px solid #4b5563;
    }
    .link-box {
      font-size: 11px;
      color: #9ca3af;
      word-break: break-all;
      padding: 8px 10px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(55, 65, 81, 0.9);
      margin-bottom: 4px;
    }
    .text-box {
      margin-top: 8px;
      padding: 10px 12px;
      border-radius: 12px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(55, 65, 81, 0.9);
      font-size: 14px;
      white-space: pre-wrap;
      word-break: break-word;
    }
    .footer {
      margin-top: 10px;
      font-size: 11px;
      color: #6b7280;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="shell">
    <div class="card">
      <div class="title">${escapeHtml(title)}</div>
      <div class="subtitle">${expired ? "Link status" : "A card shared by Lyn"}</div>

      <div class="badge">
        <span class="badge-dot"></span>
        <span id="badge-text">${expired ? "Link expired" : "Preparing to open..."}</span>
      </div>

      <div class="info" id="env-info"></div>

      ${
        card && !expired && !isTextMode
          ? '<div class="countdown">将在 <strong id="countdown-num">3</strong> 秒后尝试打开链接</div>'
          : '<div class="countdown" id="countdown-num" style="display:none;"></div>'
      }

      ${
        card && !expired && isTextMode
          ? '<div class="text-box" id="text-content">' + escapeHtml(card.target) + '</div>'
          : ''
      }

      <div class="btn-row" id="btn-row">
        ${
          card && !expired && !isTextMode
            ? '<button class="btn btn-primary" id="open-btn">立即打开</button>'
            : ''
        }
        ${
          card && !expired
            ? '<button class="btn btn-secondary" id="copy-btn">复制链接 / 内容</button>'
            : ''
        }
      </div>

      ${
        card && !expired && !isTextMode
          ? '<div class="link-box" id="link-box">' + escapeHtml(card.target) + '</div>'
          : ''
      }

      ${
        expired
          ? '<div class="text-box">链接不存在或已失效，如果是你自己生成的链接，可以在 Lyn\'s Card Maker 中重新创建一个新的。</div>'
          : ''
      }

      <div class="footer">
        Lyn\'s Card · Powered by Cloudflare Pages & KV
      </div>
    </div>
  </div>

  <script>
    (function () {
      var card = ${card ? JSON.stringify({ mode: card.mode, target: card.target }) : "null"};
      var expired = ${expired ? "true" : "false"};

      var envInfo = document.getElementById("env-info");
      var badgeText = document.getElementById("badge-text");
      var cdNum = document.getElementById("countdown-num");
      var openBtn = document.getElementById("open-btn");
      var copyBtn = document.getElementById("copy-btn");
      var linkBox = document.getElementById("link-box");

      if (!card || expired) {
        if (envInfo) {
          envInfo.textContent = "This link is invalid or has expired.";
        }
        return;
      }

      var ua = navigator.userAgent || "";
      var isWeChat = /MicroMessenger/i.test(ua);
      var isQQ = /QQ\\//i.test(ua);

      if (card.mode === "text") {
        if (envInfo) {
          envInfo.textContent = "这是一个文本卡片，不会自动跳转。";
        }
        if (badgeText) {
          badgeText.textContent = "Text card";
        }
      } else {
        if (isWeChat || isQQ) {
          if (envInfo) {
            envInfo.textContent =
              "检测到你在微信或 QQ 内打开，本页面可能无法直接跳转。请点击右上角“⋯”，选择“在浏览器中打开”后再尝试。";
          }
        } else {
          if (envInfo) {
            envInfo.textContent =
              "如果没有自动跳转，可以点击下方按钮手动打开。";
          }
        }

        var seconds = 3;
        if (cdNum) cdNum.textContent = String(seconds);

        if (!(isWeChat || isQQ)) {
          var timer = setInterval(function () {
            seconds -= 1;
            if (seconds >= 0 && cdNum) {
              cdNum.textContent = String(seconds);
            }
            if (seconds <= 0) {
              clearInterval(timer);
              try {
                window.location.href = card.target;
              } catch (e) {}
            }
          }, 1000);
        } else {
          if (cdNum && cdNum.parentElement) {
            cdNum.parentElement.textContent =
              "自动跳转已暂停，请在浏览器中打开本页面再试。";
          }
        }
      }

      if (openBtn && card.mode === "url") {
        openBtn.addEventListener("click", function () {
          try {
            window.location.href = card.target;
          } catch (e) {}
        });
      }

      if (copyBtn) {
        copyBtn.addEventListener("click", function () {
          var textToCopy = card.target;
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(textToCopy).then(function () {
              if (envInfo) envInfo.textContent = "已复制到剪贴板，可以粘贴到浏览器或聊天中。";
            }).catch(function () {
              if (envInfo) envInfo.textContent = "复制失败，请长按上方内容手动复制。";
            });
          } else {
            if (envInfo) envInfo.textContent = "当前环境不支持一键复制，请长按上方内容手动复制。";
          }
        });
      }

      if (card.mode === "text" && linkBox) {
        linkBox.style.display = "none";
      }
    })();
  </script>
</body>
</html>`;

  return new Response(html, {
    status: expired ? 410 : 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store"
    }
  });
}

export async function onRequest(context) {
  const { env, params, request } = context;
  const id = params && params.id ? String(params.id) : "";

  const url = new URL(request.url).toString();

  if (!id) {
    return renderPage({ url: url, expired: true });
  }

  const data = await env.Card_KV.get(id);
  if (!data) {
    return renderPage({ url: url, expired: true });
  }

  let card;
  try {
    card = JSON.parse(data);
  } catch (e) {
    return renderPage({ url: url, expired: true });
  }

  const now = Date.now();
  if (card.expireAt && card.expireAt > 0 && now > card.expireAt) {
    return renderPage({ card, url: url, expired: true });
  }

  return renderPage({ card, url: url, expired: false });
}
