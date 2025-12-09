/*
 * shared/utils/vless.js
 *
 * VLESS 解析器
 *
 * 支持形态：
 *   vless://uuid@host:port?encryption=none&security=tls&type=ws&host=xxx&path=/xxx&flow=xtls-rprx-vision&fp=chrome&sni=xxx#name
 *
 * 标准化输出 Node 字段：
 *   {
 *     type: "vless",
 *     name,
 *     server,
 *     port,
 *     uuid,
 *     encryption,        // none / auto ...
 *     security,          // tls / reality / none ...
 *     tls,               // true / false
 *     sni,               // sni / peer / host
 *     network,           // tcp / ws / grpc / http ...
 *     host,              // ws/http Host
 *     path,              // ws path / grpc service-name / http path
 *     flow,              // xtls-rprx-vision 等
 *     udp,               // true / false
 *     alpn,              // 字符串，渲染时转数组
 *     clientFingerprint, // chrome / safari ...
 *     realityPublicKey,  // pbk
 *     realityShortId,    // sid
 *     realitySpiderX,    // spx
 *     raw
 *   }
 */

function safeDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

export function parseVless(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw.toLowerCase().startsWith("vless://")) return null;

  // 1. 拆 #name
  let nameFromHash = "";
  let main = raw;
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    const hashPart = raw.slice(hashIndex + 1);
    nameFromHash = safeDecode(hashPart);
    main = raw.slice(0, hashIndex);
  }

  // 2. 去掉 vless://
  main = main.replace(/^vless:\/\//i, "");

  // 3. 拆 basePart?query
  let basePart = main;
  let query = "";
  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    basePart = main.slice(0, qIndex);
    query = main.slice(qIndex + 1);
  }

  // 4. basePart: uuid@host:port
  const atIndex = basePart.lastIndexOf("@");
  if (atIndex < 0) {
    return {
      type: "vless",
      raw,
      name: nameFromHash || raw,
    };
  }

  const idPart = basePart.slice(0, atIndex);
  const hostPortPart = basePart.slice(atIndex + 1);

  const uuid = idPart.trim();
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
  if (!name && params.ps) name = params.ps;
  if (!name && server && port) name = `${server}:${port}`;

  // 7. 基本字段
  const encryption = (params.encryption || "none").toString().trim();
  const security = (params.security || "").toString().trim().toLowerCase();
  let tls = false;
  if (["tls", "xtls", "reality"].includes(security)) tls = true;

  // sni / peer / host
  const sni =
    (params.sni ||
      params.peer || // 很多写法用 peer 当作 SNI
      params.host ||
      "") + "";

  // network / type
  const typeRaw = (params.type || params.net || "").toString().trim().toLowerCase();
  let network = "";
  if (typeRaw === "ws" || typeRaw === "websocket") {
    network = "ws";
  } else if (typeRaw === "grpc") {
    network = "grpc";
  } else if (typeRaw === "h2" || typeRaw === "http" || typeRaw === "httpupgrade") {
    network = "http";
  } else if (typeRaw === "tcp" || typeRaw === "") {
    network = ""; // 默认 tcp，交给渲染器补
  } else {
    network = typeRaw; // 其它直接透传
  }

  const host = (params.host || "").toString().trim();

  // path / serviceName
  const path =
    (params.path ||
      params.serviceName ||
      params["serviceName"] ||
      params["grpc-service-name"] ||
      "") + "";

  const flow = (params.flow || "").toString().trim();

  // udp：默认 true，0/false 关掉
  let udp = true;
  if (params.udp !== undefined) {
    const u = params.udp.toString().toLowerCase();
    if (["0", "false", "no"].includes(u)) udp = false;
  }

  const alpn = (params.alpn || "").toString().trim();

  const clientFingerprint =
    (params.fp || params.fingerprint || "").toString().trim();

  // Reality 相关
  const realityPublicKey =
    (params.pbk || params["publicKey"] || params["public-key"] || "").toString().trim();
  const realityShortId =
    (params.sid || params["shortId"] || params["short-id"] || "").toString().trim();
  const realitySpiderX =
    (params.spx || params["spiderX"] || params["spider-x"] || "").toString().trim();

  if (!server || !port || !uuid) {
    // 不完整也先返回，至少能看见 raw，方便调试
    return {
      type: "vless",
      raw,
      name: name || raw,
      encryption,
      security,
      tls,
      sni,
      network,
      host,
      path,
      flow,
      udp,
      alpn,
      clientFingerprint,
      realityPublicKey,
      realityShortId,
      realitySpiderX,
    };
  }

  return {
    type: "vless",
    raw,
    name: name || `${server}:${port}`,
    server,
    port,
    uuid,
    encryption,
    security,
    tls,
    sni,
    network,
    host,
    path,
    flow,
    udp,
    alpn,
    clientFingerprint,
    realityPublicKey,
    realityShortId,
    realitySpiderX,
  };
}