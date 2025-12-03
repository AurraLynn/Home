// functions/api/node-parse.js
// 简单节点识别接口：统计 ss / vmess / vless / trojan / hysteria / hysteria2 / tuic / snell / 其它 的数量

export async function onRequestPost(context) {
  const { request } = context;

  let text = "";
  try {
    text = await request.text();
  } catch (e) {
    return jsonResponse(
      { ok: false, error: "无法读取请求内容" },
      400
    );
  }

  const raw = (text || "").replace(/\r\n/g, "\n");
  const lines = raw
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);

  const stats = {
    ss: 0,
    vmess: 0,
    vless: 0,
    trojan: 0,
    hysteria: 0,
    hysteria2: 0,
    tuic: 0,
    snell: 0,
    others: 0,
  };

  const examples = {
    ss: [],
    vmess: [],
    vless: [],
    trojan: [],
    hysteria: [],
    hysteria2: [],
    tuic: [],
    snell: [],
    others: [],
  };

  for (const line of lines) {
    const lower = line.toLowerCase();

    let type = "others";

    if (lower.startsWith("ss://")) {
      type = "ss";
    } else if (lower.startsWith("vmess://")) {
      type = "vmess";
    } else if (lower.startsWith("vless://")) {
      type = "vless";
    } else if (lower.startsWith("trojan://")) {
      type = "trojan";
    } else if (lower.startsWith("hysteria2://") || lower.startsWith("hy2://")) {
      type = "hysteria2";
    } else if (lower.startsWith("hysteria://") || lower.startsWith("hy://")) {
      type = "hysteria";
    } else if (lower.startsWith("tuic://")) {
      type = "tuic";
    } else if (lower.startsWith("snell://")) {
      type = "snell";
    }

    if (!Object.prototype.hasOwnProperty.call(stats, type)) {
      stats[type] = 0;
      examples[type] = [];
    }

    stats[type] += 1;

    // 每种类型最多展示前 3 条示例
    if (examples[type].length < 3) {
      examples[type].push(line);
    }
  }

  return jsonResponse({
    ok: true,
    totalLines: lines.length,
    detected: stats,
    examples,
  });
}

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
    },
  });
}
