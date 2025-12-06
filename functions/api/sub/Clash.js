// functions/api/sub/Clash.js
//
// 用于将原始节点文本转换为 Clash / Mihomo 的 proxies 段（占位实现）。
//
// 当前行为：
// - 接收 body 中的原始文本，包装成一个简单的 proxies 段。
// - 主要目的是确保 /api/sub/Clash 路由存在并返回 200，避免 convert error。
// - 之后再逐步补充 trojan / vmess / vless / hy / hy2 等协议的具体转换逻辑。

export async function onRequestPost(context) {
  const { request } = context;
  const bodyText = (await request.text()) || "";

  // 这里只是占位：实际没有解析节点，直接把整段内容挂到一个「原始」节点里。
  // 后续会改成真实的逐条解析。
  const proxyName = "Lyn-raw";
  const yaml = [
    "proxies:",
    `  - {"name":"${proxyName}","type":"ss","server":"1.1.1.1","port":443,"cipher":"aes-128-gcm","password":"pwd","udp":true}`,
    "",
    "# 原始内容（暂未解析，仅用于调试）",
    ...bodyText.split(/\r?\n/).map((line) => "# " + line),
    "",
  ].join("\n");

  return new Response(yaml, {
    status: 200,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}