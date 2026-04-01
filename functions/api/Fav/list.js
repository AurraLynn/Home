export async function onRequestGet(context) {
  const { env } = context;
  try {
    // 从绑定的 D1 数据库 (env.DB) 中读取所有导航数据，按添加顺序倒序排列
    const { results } = await env.DB.prepare("SELECT * FROM navigation ORDER BY id DESC").all();
    return Response.json(results);
  } catch (e) {
    // 万一数据库没绑好或者表没建，给你个提示
    return Response.json({ error: "数据库查询失败，请检查 D1 绑定和建表 SQL。" }, { status: 500 });
  }
}
