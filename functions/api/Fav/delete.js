export async function onRequestPost(context) {
  const { request, env } = context;
  const { id, authCode } = await request.json();

  if (authCode !== env.ADMIN_PASSWORD) {
    return Response.json({ success: false, msg: "暗号不对，想删库？没门。" }, { status: 403 });
  }

  if (!id) return Response.json({ success: false, msg: "连个 ID 都没有你删寂寞呢？" });

  try {
    await env.DB.prepare("DELETE FROM navigation WHERE id = ?").bind(id).run();
    return Response.json({ success: true, msg: "已物理超度，灰都不剩。" });
  } catch (e) {
    return Response.json({ success: false, msg: "数据库罢工了。" }, { status: 500 });
  }
}