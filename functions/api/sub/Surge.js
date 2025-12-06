// functions/api/sub/Surge.js
//
// 用于将原始节点文本转换为 Surge 可用的订阅内容（占位实现）。
//
// 当前行为：
// - 接收 body 中的原始文本，原样返回（仅在前面加一行注释）。
// - 主要目的是确保 /api/sub/Surge 路由存在并返回 200，避免 convert error。
// - 之后再逐步补充 trojan / vmess / hy / hy2 等协议的具体转换逻辑。

export async function onRequestPost(context) {
  const { request } = context;
  const bodyText = (await request.text()) || "";

  const out = [
    "# Surge subscription (raw content)",
    "# TODO: 在这里实现节点解析并转换为 Surge 格式",
    "",
    bodyText,
  ].join("\n");

  return new Response(out, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}