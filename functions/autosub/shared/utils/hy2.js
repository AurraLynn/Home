/*
 * Hysteria2 / hy2 解析器
 *
 * 支持形态（URL 型）：
 *   1) hysteria2://password@host:port?peer=xxx&sni=yyy&insecure=1#备注
 *   2) hy2://password@host:port?peer=xxx&sni=yyy&alpn=h3#备注
 *   3) hysteria://password@host:port?...#备注   （当作 hysteria2 处理）
 *
 * 常见参数：
 *   - sni / peer            ：SNI / 证书域名
 *   - auth / password       ：密码（也可以放在前面的 password@ 里）
 *   - ports / mport         ：端口段（如 35000-39000）
 *   - up / down / upmbps    ：上下行带宽
 *   - udp                   ："1"/"true" → true
 *   - insecure / allowInsecure / skip-cert-verify：
 *                            ："1"/"true"/"yes" → skipCertVerify = true
 *
 * 输出 Node 字段（给 Normalizer / Renderer 用）：
 *   {
 *     type: "hysteria2",
 *     name,
 *     server,
 *     port,
 *     password,    // 作为通用密码字段
 *     auth,        // 等于 password，方便渲染器直接用 auth
 *     sni,
 *     peer,
 *     obfs,
 *     alpn,
 *     upmbps,
 *     downmbps,
 *     ports,
 *     udp,
 *     skipCertVerify,
 *     raw
 *   }
 */

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

export function parseHy2(url) {
  if (!url || typeof url !== "string") return null;

  const full = url.trim();
  if (!full) return null;

  // # 后面是备注
  let main = full;
  let name = "";
  const hashIndex = full.indexOf("#");
  if (hashIndex >= 0) {
    const remarkPart = full.slice(hashIndex + 1);
    main = full.slice(0, hashIndex);
    name = safeDecode(remarkPart.trim());
  }

  // 去掉协议前缀
  main = main
    .replace(/^hysteria2:\/\//i, "")
    .replace(/^hy2:\/\//i, "")
    .replace(/^hysteria:\/\//i, "");

  // 拆出 ? 参数
  let authHostPort = main;
  let search = "";
  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    authHostPort = main.slice(0, qIndex);
    search = main.slice(qIndex + 1);
  }

  // password@host:port
  let auth = "";
  let hostPort = authHostPort;
  const atIndex = authHostPort.lastIndexOf("@");
  if (atIndex >= 0) {
    auth = authHostPort.slice(0, atIndex);
    hostPort = authHostPort.slice(atIndex + 1);
  }

  auth = auth ? safeDecode(auth) : "";

  // host:port
  let server = "";
  let port = 0;
  const hpParts = hostPort.split(":");
  if (hpParts.length >= 2) {
    server = hpParts[0].trim();
    port = Number(hpParts[1].trim());
  }

  // 解析 query 参数
  const params = {};
  if (search) {
    for (const seg of search.split("&")) {
      if (!seg) continue;
      const [kRaw, vRaw = ""] = seg.split("=", 2);
      const k = (kRaw || "").trim();
      if (!k) continue;
      const key = safeDecode(k);
      const value = safeDecode(vRaw);
      params[key] = value;
    }
  }

  // 密码优先级：前缀 auth > query.auth > query.password
  const pwd = auth || params.auth || params.password || "";

  // TLS / 证书
  const sni = params.sni || params.peer || "";
  const peer = params.peer || "";

  // 其它常见参数
  const obfs = params.obfs || "";
  const alpn = params.alpn || "";
  const up = params.up || params.upmbps || "";
  const down = params.down || params.downmbps || "";
  const ports = params.ports || params.mport || "";
  const udp = params.udp === "1" || params.udp === "true";

  const insecureFlag =
    params.insecure ||
    params.allowInsecure ||
    params["skip-cert-verify"];

  const skipCertVerify =
    insecureFlag === "1" ||
    insecureFlag === "true" ||
    insecureFlag === "yes";

  // 关键字段缺失时，退一个最小结构，避免整条崩掉
  if (!server || !port || !pwd) {
    return {
      type: "hysteria2",
      name: name || full,
      raw: full,
    };
  }

  const node = {
    type: "hysteria2",
    name: name || `${server}:${port}`,
    server,
    port,
    password: pwd,
    auth: pwd, // 渲染器直接用 auth 即可
    sni,
    peer,
    obfs,
    alpn,
    upmbps: up,
    downmbps: down,
    ports,
    udp,
    skipCertVerify,
    raw: full,
  };

  return node;
}
