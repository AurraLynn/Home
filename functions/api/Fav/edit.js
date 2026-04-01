export async function onRequestPost(context) {
  const { request, env } = context;
  const { id, title, category, authCode } = await request.json();

  if (authCode !== env.ADMIN_PASSWORD) {
    return Response.json({ success: false, msg: "没密码你改个屁。" }, { status: 403 });
  }

  if (!id || !title) return Response.json({ success: false, msg: "名字和 ID 必须填！" });

  try {
    await env.DB.prepare(
      "UPDATE navigation SET title = ?, category = ? WHERE id = ?"
    ).bind(title, category || "Default", id).run();
    return Response.json({ success: true, msg: "狗牌已翻新。" });
  } catch (e) {
    return Response.json({ success: false, msg: "数据库罢工了。" }, { status: 500 });
  }
}