/*
 * shared/utils/trojan.js
 *
 * Trojan 解析器
 *
 * 支持：
 *   1) 最基础：
 *      trojan://password@host:port#name
 *
 *   2) 带参数（常见机场写法）：
 *      trojan://password@host:port?peer=xx.com&sni=xx.com&obfs=grpc#name
 *      trojan://password@host:port?peer=xx.com&obfs=ws&path=/xxx#name
 *
 * 标准化输出 Node 字段：
 *   {
 *     type: "trojan",
 *     name,
 *     server,
 *     port,
 *     password,
 *     sni,        // sni / peer / host
 *     network,    // "", grpc, ws ...
 *     path,       // grpc serviceName / ws path
 *     obfs,       // 原始 obfs/type 参数
 *     raw,
 *   }
 */

function safeDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

export function parseTrojan(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw.toLowerCase().startsWith("trojan://")) return null;

  // 1. 拆备注 #name
  let nameFromHash = "";
  let main = raw;
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    const hashPart = raw.slice(hashIndex + 1);
    nameFromHash = safeDecode(hashPart);
    main = raw.slice(0, hashIndex);
  }

  // 2. 去掉 trojan:// 前缀
  main = main.replace(/^trojan:\/\//i, "");

  // 3. 拆 query：basePart?query
  let basePart = main;
  let query = "";
  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    basePart = main.slice(0, qIndex);
    query = main.slice(qIndex + 1);
  }

  // 4. basePart: password@host:port
  const atIndex = basePart.lastIndexOf("@");
  if (atIndex < 0) {
    return {
      type: "trojan",
      raw,
      name: nameFromHash || raw,
    };
  }

  const passPart = basePart.slice(0, atIndex); // password
  const hostPortPart = basePart.slice(atIndex + 1); // host:port

  const password = passPart.trim();
  const [serverRaw, portStr] = hostPortPart.split(":", 2);
  const server = (serverRaw || "").trim();
  const port = Number((portStr || "").trim() || 0);

  // 5. 解析 query 参数
  const params = {};
  if (query) {
    const segs = query.split("&");
    for (const seg of segs) {
      if (!seg) continue;
      const [kRaw, vRaw = ""] = seg.split("=", 2);
      const k = (kRaw || "").trim();
      if (!k) continue;
      const key = safeDecode(k);
      const val = safeDecode(vRaw);
      params[key] = val;
    }
  }

  // 6. 名称
  let name = nameFromHash;
  if (!name && params.remarks) name = params.remarks;
  if (!name && server && port) name = `${server}:${port}`;

  // 7. sni / peer / host
  const sni =
    (params.sni ||
      params.peer || // 很多机场 trojan-grpc 用 peer
      params.host ||
      "") + "";

  // 8. 传输方式 / 混淆：grpc / ws / websocket / ...
  const obfs = (params.obfs || params.type || "").toLowerCase();
  let network = "";
  if (obfs === "grpc") {
    network = "grpc";
  } else if (obfs === "ws" || obfs === "websocket") {
    network = "ws";
  } else {
    network = ""; // 默认 tcp
  }

  // 9. path / serviceName
  // trojan-grpc 常见参数：serviceName=/xxx 或 path=/xxx
  const path =
    params.serviceName ||
    params["serviceName"] ||
    params.path ||
    params["grpc-service-name"] ||
    "";

  if (!server || !port || !password) {
    return {
      type: "trojan",
      raw,
      name: name || raw,
      sni,
      network,
      path,
      obfs,
    };
  }

  return {
    type: "trojan",
    raw,
    name: name || `${server}:${port}`,
    server,
    port,
    password,
    sni,
    network, // "", grpc, ws
    path,
    obfs,
  };
}