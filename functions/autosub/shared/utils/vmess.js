/*
 * shared/utils/vmess.js
 *
 * VMess 解析器
 *
 * 支持两种形态：
 *
 * 1) JSON 型（主流机场写法）：
 *    vmess://BASE64(JSON)
 *
 *    JSON 常见字段：
 *      v, ps, add, port, id, aid, scy/security, net, type, host, path,
 *      tls, sni, alpn, udp, ...
 *
 * 2) 老式 URL 型（你发的那几条）：
 *    vmess://BASE64(auto:uuid@host:port)?path=/&remarks=...&obfsParam=...&obfs=http/websocket&tfo=1&alterId=0
 *
 * 标准化输出 Node 字段：
 *   {
 *     type: "vmess",
 *     name,
 *     server,
 *     port,
 *     uuid,
 *     alterId,
 *     cipher,     // auto / aes-128-gcm / chacha20-ietf-poly1305 ...
 *     network,    // tcp / ws / http / grpc ...
 *     host,       // ws / http Host
 *     path,       // ws path / http path / grpc service-name
 *     tls,        // true / false
 *     sni,
 *     tfo,        // true / false
 *     obfs,       // http / websocket / ...
 *     raw
 *   }
 */

function b64DecodeUrlSafe(input) {
  if (!input) return "";
  let s = String(input).trim().replace(/-/g, "+").replace(/_/g, "/");

  const pad = s.length % 4;
  if (pad) s += "=".repeat(4 - pad);

  // 尝试 UTF-8 解码，避免 JSON 里有中文时解析失败
  try {
    return decodeURIComponent(escape(atob(s)));
  } catch {
    try {
      return atob(s);
    } catch {
      return "";
    }
  }
}

function safeDecode(str) {
  try {
    return decodeURIComponent(str);
  } catch {
    return str;
  }
}

export function parseVmess(line) {
  const raw = String(line || "").trim();
  if (!raw.startsWith("vmess://")) return null;

  // 1. 拆 # 备注
  let nameFromHash = "";
  let main = raw;
  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    const hashPart = raw.slice(hashIndex + 1);
    nameFromHash = safeDecode(hashPart);
    main = raw.slice(0, hashIndex);
  }

  // 2. 去掉 vmess:// 前缀
  main = main.replace(/^vmess:\/\//i, "");

  // 3. basePart?query
  let basePart = main;
  let query = "";
  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    basePart = main.slice(0, qIndex);
    query = main.slice(qIndex + 1);
  }

  // 4. base64 解码：JSON or "auto:uuid@host:port"
  const decoded = b64DecodeUrlSafe(basePart);
  if (!decoded) {
    return {
      type: "vmess",
      raw,
      name: nameFromHash || raw,
    };
  }

  const dTrim = decoded.trim();

  // ===== 4.1 JSON 型：vmess://BASE64(JSON) =====
  if (dTrim.startsWith("{") && dTrim.endsWith("}")) {
    try {
      const obj = JSON.parse(dTrim);

      const server = String(obj.add || "").trim();
      const port = Number(obj.port || 0);
      const uuid = String(obj.id || "").trim();
      const alterId = Number(obj.aid || 0);

      const cipher =
        String(obj.scy || obj.security || obj.cipher || "auto").trim() ||
        "auto";

      const net = String(obj.net || "").trim().toLowerCase();
      const host = String(obj.host || "").trim();
      const path = String(obj.path || "").trim();

      let tls = false;
      const tlsField =
        String(obj.tls || obj.security || "").trim().toLowerCase();
      if (tlsField === "tls" || tlsField === "1" || tlsField === "true") {
        tls = true;
      }
      const sni = String(obj.sni || obj.servername || "").trim();

      let name = nameFromHash || String(obj.ps || "").trim();
      if (!name && server && port) name = `${server}:${port}`;

      if (!server || !port || !uuid) {
        return { type: "vmess", raw, name: name || raw };
      }

      return {
        type: "vmess",
        raw,
        name,
        server,
        port,
        uuid,
        alterId,
        cipher,
        network: net, // tcp / ws / http / grpc / ...
        host,
        path,
        tls,
        sni,
        tfo: false,
        obfs: "", // JSON 型通常没有单独 obfs
      };
    } catch {
      // JSON 失败就继续走老式 auto:uuid@host:port 逻辑
    }
  }

  // ===== 4.2 非 JSON：期待 auto:uuid@host:port =====
  const atIndex = decoded.lastIndexOf("@");
  if (atIndex < 0) {
    return {
      type: "vmess",
      raw,
      name: nameFromHash || raw,
    };
  }

  const left = decoded.slice(0, atIndex); // auto:uuid
  const right = decoded.slice(atIndex + 1); // host:port

  const [methodRaw, uuidRaw] = left.split(":", 2);
  const [serverRaw, portStr] = right.split(":", 2);

  const uuid = (uuidRaw || "").trim();
  const server = (serverRaw || "").trim();
  const port = Number((portStr || "").trim());
  const cipher = (methodRaw || "auto").trim() || "auto";

  // 解析 query 参数：path / remarks / obfs / obfsParam / tfo / alterId
  const params = {};
  if (query) {
    const pairs = query.split("&");
    for (const seg of pairs) {
      if (!seg) continue;
      const [kRaw, vRaw = ""] = seg.split("=", 2);
      const k = (kRaw || "").trim();
      if (!k) continue;

      const key = safeDecode(k);
      const val = safeDecode(vRaw);
      params[key] = val;
    }
  }

  let name = nameFromHash;
  if (!name && params.remarks) name = params.remarks;

  const alterId = params.alterId ? Number(params.alterId) || 0 : 0;

  const obfs = String(params.obfs || "").toLowerCase();
  const obfsParam = params.obfsParam || "";
  const path = params.path || "";

  let network = "";
  let host = "";

  if (obfs === "websocket" || obfs === "ws") {
    // vmess + ws
    network = "ws";
    host = obfsParam;
  } else if (obfs === "http") {
    // vmess + tcp + http 伪装
    network = "http";
    host = obfsParam;
  } else {
    network = ""; // 让渲染器默认走 tcp
  }

  const tfo =
    params.tfo === "1" ||
    params.tfo === "true" ||
    params.tfo === "yes" ||
    params.tfo === "on";

  if (!server || !port || !uuid) {
    return {
      type: "vmess",
      raw,
      name: name || raw,
    };
  }

  return {
    type: "vmess",
    raw,
    name: name || `${server}:${port}`,
    server,
    port,
    uuid,
    alterId,
    cipher,
    network, // "" / ws / http
    host,
    path,
    tfo,
    obfs,
  };
}