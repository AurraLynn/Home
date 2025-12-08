/**
 * Quantumult X Renderer (占位版)
 * - 你说“其他客户端不需要包一层配置”
 * - 当前阶段先保证链路可用
 * - 后续你再逐协议补 QX 的真实节点语法
 */
export function renderQX(nodes = []) {
  const lines = [];

  lines.push("# Quantumult X passthrough (autosub)");
  lines.push("# parsed nodes:");

  for (const n of nodes) {
    if (!n) continue;
    lines.push(`# ${n.type || "unknown"}: ${n.raw || ""}`);
  }

  // 当前先不生成 QX 真正 profile
  // 只保证不报错 + 方便你确认解析链路
  return {
    body: lines.join("\n"),
    contentType: "text/plain; charset=utf-8",
  };
}
