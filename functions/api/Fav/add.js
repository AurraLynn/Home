export async function onRequestPost(context) {
  const { request, env } = context;
  const { url, category, authCode } = await request.json();

  // 1. 验证你的后台暗号
  if (authCode !== env.ADMIN_PASSWORD) {
    return Response.json({ success: false, msg: "暗号不对，爬。" }, { status: 403 });
  }

  let icon = "";
  let title = "";

  try {
    const targetUrl = new URL(url.startsWith('http') ? url : 'https://' + url);
    const domain = targetUrl.hostname;

    // 2. 暴力抓取策略
    if (domain.includes('t.me')) {
      const res = await fetch(url);
      const html = await res.text();
      icon = html.match(/<meta property="og:image" content="(.*?)"/)?.[1] || "";
      title = html.match(/<meta property="og:title" content="(.*?)"/)?.[1] || "TG 频道";
    } 
    else if (domain.includes('apps.apple.com')) {
      const appId = url.match(/id(\d+)/)?.[1];
      const res = await fetch(`https://itunes.apple.com/lookup?id=${appId}`);
      const data = await res.json();
      icon = data.results[0]?.artworkUrl512 || "";
      title = data.results[0]?.trackName || "iOS App";
    } 
    else {
      // 默认抓取
      icon = `https://icons.duckduckgo.com/ip3/${domain}.ico`;
      title = domain;
    }

    // 3. 写入 D1 数据库 (确保你在 CF 后台绑定的变量名是 DB)
    await env.DB.prepare(
      "INSERT INTO navigation (title, url, icon_url, category) VALUES (?, ?, ?, ?)"
    ).bind(title, url, icon, category || "默认分类").run();

    return Response.json({ 
      success: true, 
      msg: "图标扒到了，优雅。", 
      data: { title, icon } 
    });

  } catch (e) {
    return Response.json({ success: false, msg: "这网址有毒，解析不动。" }, { status: 500 });
  }
}
