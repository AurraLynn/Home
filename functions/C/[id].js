// functions/C/[id].js

function escapeHtml(str) {
    if (!str) return "";
    return String(str).replace(/[&<>"']/g, (ch) => {
        switch (ch) {
            case "&":
                return "&amp;";
            case "<":
                return "&lt;";
            case ">":
                return "&gt;";
            case '"':
                return "&quot;";
            case "'":
                return "&#39;";
            default:
                return ch;
        }
    });
}

function renderPage(options) {
    const card = options.card || null;
    const url = options.url;           // 干净的短链接（无查询参数）
    const expired = !!options.expired;

    const title = card && card.title ? card.title : "Lyn's Card";
    const desc = card && card.description
        ? card.description
        : (expired ? "This link has expired." : "A card shared by Lyn.");
    const image = card && card.image
        ? card.image
        : "https://save.aura.us.kg/Picture/Preview/YL1.png";

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
      background: #f3f4f6;
      color: #111827;
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
      background: #ffffff;
      border-radius: 20px;
      padding: 20px 18px 18px;
      border: 1px solid #e5e7eb;
      box-shadow: 0 18px 35px rgba(15, 23, 42, 0.12);
    }
    .title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 4px;
      text-align: center;
    }
    .subtitle {
      font-size: 13px;
      color: #6b7280;
      text-align: center;
      margin-bottom: 14px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
      border: 1px solid #e5e7eb;
      background: #f9fafb;
      font-size: 11px;
      color: #4b5563;
      margin: 0 auto 14px;
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
      color: #6b7280;
      text-align: center;
      margin-bottom: 8px;
      min-height: 32px;
    }
    .countdown {
      font-size: 12px;
      text-align: center;
      margin-bottom: 12px;
      color: #111827;
    }
    .countdown strong {
      font-size: 16px;
    }
    .btn-row {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      justify-content: center;
      margin-bottom: 10px;
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
      background: #111827;
      color: #f9fafb;
    }
    .btn-secondary {
      background: #e5e7eb;
      color: #111827;
    }
    .link-box {
      font-size: 11px;
      color: #6b7280;
      word-break: break-all;
      padding: 8px 10px;
      border-radius: 12px;
      background: #f9fafb;
      border: 1px solid #e5e7eb;
      margin-bottom: 6px;
    }
    .text-box {
      margin-top: 8px;
      padding: 10px 12px;
      border-radius: 12px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      font-size: 13px;
      color: #b91c1c;
      white-space: pre-wrap;
      word-break: break-word;
      text-align: center;
    }
    .footer {
      margin-top: 10px;
      font-size: 11px;
      color: #9ca3af;
      text-align: center;
    }
    /* 微信 / QQ 强提示块 */
    .wx-strong {
      margin: 6px 0 10px;
      padding: 10px 12px;
      border-radius: 12px;
      background: #fef2f2;
      border: 1px solid #fecaca;
      font-size: 14px;
      color: #b91c1c;
      text-align: center;
      font-weight: 600;
      line-height: 1.5;
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
        !expired
            ? '<div class="countdown">将在 <strong id="countdown-num">3</strong> 秒后尝试打开链接</div>'
            : '<div class="countdown" id="countdown-num" style="display:none;"></div>'
    }

      <!-- 微信 / QQ 强提示 -->
      <div class="wx-strong" id="wx-warning" style="display:none;">
        检测到你在 <strong>微信 / QQ</strong> 内打开。<br>
        如 <strong>3 秒后仍未跳转</strong>，请点击右上角
        <strong>“···” → 用浏览器打开</strong> 谢谢。☺️
      </div>

      <div class="btn-row" id="btn-row">
        ${!expired ? '<button class="btn btn-primary" id="share-btn">立即打开</button>' : ''}
        ${!expired ? '<button class="btn btn-secondary" id="copy-btn">复制链接</button>' : ''}
      </div>

      ${
        !expired
            ? '<div class="link-box" id="link-box">' + escapeHtml(card ? card.target : "") + '</div>'
            : ''
    }

      ${
        expired
            ? '<div class="text-box">链接不存在或已失效，如果是你自己生成的链接，可以在 Lyn\'s Card Maker 中重新创建一个新的。</div>'
            : ''
    }

      <div class="footer">
        Lyn&#39;s Card · Powered by Cloudflare Pages
      </div>
    </div>
  </div>

  <script>
    (function () {
      var card = ${card ? JSON.stringify({ target: card.target }) : "null"};
      var expired = ${expired ? "true" : "false"};

      var envInfo = document.getElementById("env-info");
      var badgeText = document.getElementById("badge-text");
      var cdNum = document.getElementById("countdown-num");
      var shareBtn = document.getElementById("share-btn");
      var copyBtn = document.getElementById("copy-btn");
      var wxWarning = document.getElementById("wx-warning");

      if (!card || expired) {
        if (envInfo) {
          envInfo.textContent = "This link is invalid or has expired.";
        }
        return;
      }

      var ua = navigator.userAgent || "";
      var isWeChat = /MicroMessenger/i.test(ua);
      var isQQ = /QQ\\//i.test(ua);

      if (isWeChat || isQQ) {
        if (envInfo) {
          envInfo.textContent =
            "当前在微信 / QQ 内打开，本页面会尝试自动跳转，如无法跳转请按提示在浏览器中打开。";
        }
        if (badgeText) {
          badgeText.textContent = "WeChat / QQ detected";
        }
        if (wxWarning) {
          wxWarning.style.display = "block";
        }
      } else {
        if (envInfo) {
          envInfo.textContent = "如果没有自动跳转，可以点击下方按钮分享或复制。";
        }
      }

      // 当前页面完整 URL（可能会被 QQ / 微信加上 ?qq_xxx）
      var rawUrl = window.location.href;

      // 构造「干净短链接」：只保留 origin + pathname，去掉所有 ? 和 #
      var cardUrl;
      try {
        var u = new URL(rawUrl);
        cardUrl = u.origin + u.pathname;
      } catch (e) {
        cardUrl = rawUrl.split("#")[0].split("?")[0];
      }

      // 3 秒自动跳转到目标链接
      var seconds = 3;
      if (cdNum) cdNum.textContent = String(seconds);

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

      // 「立即打开」按钮：保留系统分享功能，但只分享短链接（不带标题 text）
      if (shareBtn) {
        if (!navigator.share) {
          // 不支持 Web Share API 的时候，禁用按钮
          shareBtn.disabled = true;
          shareBtn.style.opacity = "0.6";
          // 文案还是显示“立即打开”，但点了没反应；提示交给下面 info 文案
        }

        shareBtn.addEventListener("click", function () {
          if (!navigator.share) {
            if (envInfo) {
              envInfo.textContent = "当前浏览器不支持系统分享，请使用复制链接。";
            }
            return;
          }

          // ✅ 只分享短链接，不带 title / text
          navigator.share({
            url: cardUrl
          }).catch(function (err) {
            // 用户取消不算错误
            console.log("share canceled or failed", err);
          });
        });
      }

      // 复制链接按钮：复制干净短链接
      if (copyBtn) {
        copyBtn.addEventListener("click", function () {
          var textToCopy = cardUrl;

          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(textToCopy).then(function () {
              if (envInfo) envInfo.textContent = "已复制卡片链接，可以粘贴到浏览器或聊天中。";
            }).catch(function () {
              if (envInfo) envInfo.textContent = "复制失败，请长按地址栏链接手动复制。";
            });
          } else {
            if (envInfo) envInfo.textContent = "当前环境不支持一键复制，请长按地址栏链接手动复制。";
          }
        });
      }
    })();
  </script>
</body>
</html>`;

    return new Response(html, {
        status: expired ? 410 : 200,
        headers: {
            "content-type": "text/html; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}

export async function onRequest(context) {
    const { env, params, request } = context;
    const id = params && params.id ? String(params.id) : "";

    // 干净短链接（不带查询）
    const reqUrl = new URL(request.url);
    const cleanUrl = reqUrl.origin + reqUrl.pathname;

    if (!id) {
        return renderPage({ url: cleanUrl, expired: true });
    }

    const data = await env.Card_KV.get(id);
    if (!data) {
        return renderPage({ url: cleanUrl, expired: true });
    }

    let card;
    try {
        card = JSON.parse(data);
    } catch (e) {
        return renderPage({ url: cleanUrl, expired: true });
    }

    const now = Date.now();
    if (card.expireAt && card.expireAt > 0 && now > card.expireAt) {
        return renderPage({ card, url: cleanUrl, expired: true });
    }

    return renderPage({ card, url: cleanUrl, expired: false });
}