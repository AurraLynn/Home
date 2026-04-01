export async function onRequestPost(context) {
  const { request, env } = context;
  const { url, category, authCode } = await request.json();

  // 1. 验证你的后台暗号 (ADMIN_PASSWORD 需要在 Cloudflare 环境变量里设置)
  if (authCode !== env.ADMIN_PASSWORD) {
    return Response.json({ success: false, msg: "暗号不对，爬。" }, { status: 403 });
  }

  let icon = "";
  let title = "";

  try {
    // 补全 http 协议头，防止解析报错
    const targetUrl = new URL(url.startsWith('http') ? url : 'https://' + url);
    const domain = targetUrl.hostname;

    // 2. 针对不同平台的暴力抓取策略
    if (domain.includes('t.me')) {
      // TG 频道抓取头像
      const res = await fetch(url);
      const html = await res.text();
      icon = html.match(/<meta property="og:image" content="(.*?)"/)?.[1] || "";
      title = html.match(/<meta property="og:title" content="(.*?)"/)?.[1] || "TG 频道";
    } 
    else if (domain.includes('apps.apple.com')) {
      // App Store 抓取高清图标
      const appId = url.match(/id(\d+)/)?.[1];
      const res = await fetch(`https://itunes.apple.com/lookup?id=${appId}`);
      const data = await res.json();
      icon = data.results[0]?.artworkUrl512 || "";
      title = data.results[0]?.trackName || "iOS App";
    } 
    else {
      // 普通网站：使用 DuckDuckGo 的 favicon 服务（比 Google 的清晰一点）
      icon = `https://icons.duckduckgo.com/ip3/${domain}.ico`;
      title = domain;
    }

    // 3. 写入 D1 数据库
    await env.DB.prepare(
      "INSERT INTO navigation (title, url, icon_url, category) VALUES (?, ?, ?, ?)"
    ).bind(title, url, icon, category || "默认分类").run();

    // 4. 返回阴阳怪气的成功提示
    return Response.json({ 
      success: true, 
      msg: "图标扒到了，希望你这脚本跑起来别又断流。", 
      data: { title, icon } 
    });

  } catch (e) {
    return Response.json({ success: false, msg: "这网址有毒，解析不动。" }, { status: 500 });
  }
}
