/*
 * VMess 解析器
 *
 * 支持两种形态：
 *
 * 1) JSON 型（主流）：
 *    vmess://BASE64(JSON)
 *
 *    JSON 常见字段：
 *      v, ps, add, port, id, aid, scy/security, net, type, host, path,
 *      tls, sni, alpn, udp, ...
 *
 * 2) URL 型：
 *    vmess://uuid@host:port?encryption=auto&security=tls&type=ws&host=xxx&path=/xxx#备注
 *
 * 标准化输出 Node 字段：
 *   {
 *     type: "vmess",
 *     name,
 *     server,
 *     port,
 *     uuid,
 *     alterId,
 *     cipher,        // 加密算法：auto / aes-128-gcm / chacha20-ietf-poly1305 ...
 *     network,       // tcp / ws / grpc / kcp / http ...
 *     headerType,    // type 字段，通常为 "none"
 *     tls,           // true / false
 *     sni,
 *     alpn,          // 字符串 or 数组串联
 *     host,          // Host 头（ws/ tcp http）
 *     path,          // ws 路径 / http path / grpc service-name
 *     udp,           // true / false
 *     raw            // 原始整串
 *   }
 */

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");

  // padding
  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  try {
    // 兼容 UTF-8
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

function safeDecode(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function parseJsonStyle(body, remark, raw) {
  const decoded = b64DecodeUrlSafe(body);
  if (!decoded || decoded[0] !== "{") return null;

  let obj;
  try {
    obj = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object") return null;

  const name = (remark || obj.ps || "").trim();
  const server = (obj.add || "").trim();
  const port = Number(obj.port || 0);
  const uuid = (obj.id || "").trim();

  if (!server || !port || !uuid) {
    return {
      type: "vmess",
      name: name || raw,
      raw,
    };
  }

  const alterId = Number(obj.aid || 0);
  const cipher =
    (obj.scy || obj.security || obj.cipher || "auto").toString().trim() ||
    "auto";
  const network = (obj.net || "").toString().trim().toLowerCase();
  const headerType = (obj.type || "").toString().trim().toLowerCase();
  const host = (obj.host || "").toString().trim();
  const path = (obj.path || "").toString().trim();

  let tls = false;
  const tlsField = (obj.tls || obj.security || "").toString().toLowerCase();
  if (tlsField === "tls" || tlsField === "1" || tlsField === "true") {
    tls = true;
  }

  const sni = (obj.sni || obj.servername || "").toString().trim();
  let alpn = "";
  if (Array.isArray(obj.alpn)) {
    alpn = obj.alpn.join(",");
  } else if (obj.alpn) {
    alpn = String(obj.alpn);
  }

  const udp =
    obj.udp === true ||
    obj.udp === 1 ||
    (typeof obj.udp === "string" &&
      ["1", "true", "yes"].includes(obj.udp.toLowerCase()));

  return {
    type: "vmess",
    name: name || `${server}:${port}`,
    server,
    port,
    uuid,
    alterId,
    cipher,
    network,
    headerType,
    tls,
    sni,
    alpn,
    host,
    path,
    udp,
    raw,
  };
}

function parseUrlStyle(body, remark, raw) {
  // 先剥掉 vmess://
  let main = body;
  main = main.replace(/^vmess:\/\//i, "");

  // 拆 # 备注
  let name = remark;
  let withoutHash = main;
  const hashIdx = main.indexOf("#");
  if (hashIdx >= 0) {
    const r = main.slice(hashIdx + 1);
    withoutHash = main.slice(0, hashIdx);
    if (!name) name = safeDecode(r.trim());
  }

  // 拆 query
  let beforeQuery = withoutHash;
  let search = "";
  const qIdx = withoutHash.indexOf("?");
  if (qIdx >= 0) {
    beforeQuery = withoutHash.slice(0, qIdx);
    search = withoutHash.slice(qIdx + 1);
  }

  // uuid@host:port
  let uuid = "";
  let hostPort = beforeQuery;
  const atIdx = beforeQuery.lastIndexOf("@");
  if (atIdx >= 0) {
    uuid = beforeQuery.slice(0, atIdx).trim();
    hostPort = beforeQuery.slice(atIdx + 1).trim();
  }

  // host:port
  const hpParts = hostPort.split(":");
  const server = (hpParts[0] || "").trim();
  const port = Number((hpParts[1] || "").trim());

  const params = {};
  if (search) {
    for (const seg of search.split("&")) {
      if (!seg) continue;
      const [kRaw, vRaw = ""] = seg.split("=", 2);
      const k = (kRaw || "").trim();
      if (!k) continue;
      const key = safeDecode(k);
      const val = safeDecode(vRaw);
      params[key] = val;
    }
  }

  // uuid 最终来源：前缀 / query.id / query.uuid
  const uuidFinal =
    uuid ||
    (params.id ? params.id.trim() : "") ||
    (params.uuid ? params.uuid.trim() : "");

  if (!server || !port || !uuidFinal) {
    return {
      type: "vmess",
      name: name || raw,
      raw,
    };
  }

  const cipher =
    (params.encryption ||
      params.scy ||
      params.cipher ||
      params.security ||
      "auto") || "auto";

  const network = (
    params.type ||
    params.net ||
    params.network ||
    ""
  ).toString().toLowerCase();

  let tls = false;
  const sec = (params.security || params.tls || "").toString().toLowerCase();
  if (["tls", "xtls", "reality"].includes(sec)) {
    tls = true;
  }
  if (["1", "true", "yes"].includes(sec)) {
    tls = true;
  }

  const sni =
    (params.sni ||
      params.servername ||
      params["server-name"] ||
      params.peer ||
      "") + "";

  const host =
    (params.host ||
      params["ws-headers-host"] ||
      params["wsHost"] ||
      params["ws-host"] ||
      "") + "";

  const path =
    (params.path ||
      params["ws-path"] ||
      params["wsPath"] ||
      params["grpc-service-name"] ||
      "") + "";

  const udp =
    params.udp === "1" ||
    params.udp === "true" ||
    params.udp === "yes" ||
    params.udp === "on";

  const alterId = params.aid ? Number(params.aid) : 0;

  return {
    type: "vmess",
    name: name || `${server}:${port}`,
    server,
    port,
    uuid: uuidFinal,
    alterId,
    cipher: cipher || "auto",
    network,
    headerType: "",
    tls,
    sni: sni.trim(),
    alpn: "",
    host: host.trim(),
    path: path.trim(),
    udp,
    raw,
  };
}

export function parseVmess(url) {
  if (!url || typeof url !== "string") return null;
  const raw = url.trim();
  if (!raw) return null;

  let main = raw;
  let remark = "";
  const hashIdx = raw.indexOf("#");
  if (hashIdx >= 0) {
    remark = safeDecode(raw.slice(hashIdx + 1).trim());
    main = raw.slice(0, hashIdx);
  }

  // 去前缀 vmess://
  let body = main.replace(/^vmess:\/\//i, "");

  // 先尝试 JSON 型 base64
  const asJson = parseJsonStyle(body, remark, raw);
  if (asJson) return asJson;

  // 再尝试 URL 型
  const asUrl = parseUrlStyle(main, remark, raw);
  if (asUrl) return asUrl;

  return {
    type: "vmess",
    name: remark || raw,
    raw,
  };
}