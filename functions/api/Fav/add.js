export async function onRequestPost(context) {
  const { request, env } = context;
  const { url, category, authCode } = await request.json();

  if (authCode !== env.ADMIN_PASSWORD) {
    return Response.json({ success: false, msg: "暗号不对，爬。" }, { status: 403 });
  }

  let finalIcon = "";
  let finalTitle = "";
  let finalRemark = ""; 
  let targetUrl = url;

  if (!targetUrl.includes('://')) { targetUrl = 'https://' + targetUrl; }

  try {
    const urlObj = new URL(targetUrl);
    const domain = urlObj.hostname;
    const protocol = urlObj.protocol;

    if (protocol !== 'http:' && protocol !== 'https:') {
      finalTitle = protocol.replace(':', ' Protocol');
      finalIcon = 'https://api.iconify.design/logos:apple-app-store.svg'; 
      finalRemark = "本地应用唤醒链接";
    } else {
      finalIcon = `https://www.google.com/s2/favicons?domain=${domain}&sz=256`;
      finalTitle = domain;
      
      try {
        const res = await fetch(targetUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } });
        const html = await res.text();
        
        // 抓取标题
        const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
        if (titleMatch) finalTitle = titleMatch[1].trim();
        
        // 抓取简介 (Description)
        const descMatch = html.match(/<meta[^>]*name="description"[^>]*content="([^"]*)"[^>]*>/i) || 
                          html.match(/<meta[^>]*property="og:description"[^>]*content="([^"]*)"[^>]*>/i);
        
        if (descMatch && descMatch[1].trim() !== "") {
            finalRemark = descMatch[1].trim();
        } else {
            // 如果没有简介，把标题当做备注兜底，拒绝空荡荡
            finalRemark = titleMatch ? titleMatch[1].trim() : "这破站连个简介都没有";
        }
      } catch (e) {
        finalRemark = "防爬虫太严，偷不到简介。";
      }
    }

    // 强制截取长度并存入 category 字段
    const saveCategory = finalRemark ? finalRemark.substring(0, 60) + "..." : "暂无备注";

    await env.DB.prepare(
      "INSERT INTO navigation (title, url, icon_url, category) VALUES (?, ?, ?, ?)"
    ).bind(finalTitle, targetUrl, finalIcon, saveCategory).run();

    return Response.json({ success: true, msg: "已强行收录并偷走简介。" });

  } catch (e) {
    return Response.json({ success: false, msg: "链接格式稀烂，解析暴毙。" }, { status: 500 });
  }
}
