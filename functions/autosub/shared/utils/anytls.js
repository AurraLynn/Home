/*
 * 文件路径：functions/autosub/shared/utils/anytls.js
 * 文件作用：
 *   - 解析 anytls:// 分享链接
 *   - 输出标准 Node，供 clash / mihomo 渲染器使用
 *
 * 支持格式：
 *   anytls://password@example.com:443/?sni=real.example.com&insecure=1#AnyTLS
 *   anytls://password@example.com:443/?peer=real.example.com&allowInsecure=true#AnyTLS
 */

function safeDecode(s) {
  try {
    return decodeURIComponent(s || "");
  } catch {
    return s || "";
  }
}

function parseBool(v) {
  const s = String(v ?? "").trim().toLowerCase();
  return s === "1" || s === "true" || s === "yes";
}

function splitHostPort(hostPort) {
  const s = String(hostPort || "").trim();
  if (!s) return ["", 0];

  // IPv6: [::1]:443
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end >= 0) {
      const host = s.slice(1, end);
      const rest = s.slice(end + 1);
      const port = rest.startsWith(":") ? Number(rest.slice(1)) || 0 : 0;
      return [host, port];
    }
  }

  const idx = s.lastIndexOf(":");
  if (idx < 0) return [s, 443];

  const host = s.slice(0, idx).trim();
  const port = Number(s.slice(idx + 1).trim()) || 443;

  return [host, port];
}

function parseQuery(query) {
  const params = {};
  const q = String(query || "").replace(/^\?/, "");

  if (!q) return params;

  for (const seg of q.split("&")) {
    if (!seg) continue;

    const eq = seg.indexOf("=");
    const k = eq >= 0 ? seg.slice(0, eq) : seg;
    const v = eq >= 0 ? seg.slice(eq + 1) : "";

    const key = safeDecode(k).trim();
    if (!key) continue;

    params[key] = safeDecode(v);
  }

  return params;
}

export function parseAnyTLS(input) {
  if (!input || typeof input !== "string") return null;

  const raw = input.trim();
  if (!raw.toLowerCase().startsWith("anytls://")) return null;

  let main = raw;
  let nameFromHash = "";

  const hashIndex = raw.indexOf("#");
  if (hashIndex >= 0) {
    nameFromHash = safeDecode(raw.slice(hashIndex + 1).trim());
    main = raw.slice(0, hashIndex);
  }

  main = main.replace(/^anytls:\/\//i, "");

  let basePart = main;
  let query = "";

  const qIndex = main.indexOf("?");
  if (qIndex >= 0) {
    basePart = main.slice(0, qIndex);
    query = main.slice(qIndex + 1);
  }

  let password = "";
  let hostPort = basePart;

  const atIndex = basePart.lastIndexOf("@");
  if (atIndex >= 0) {
    password = safeDecode(basePart.slice(0, atIndex));
    hostPort = basePart.slice(atIndex + 1);
  }

  const [server, port] = splitHostPort(hostPort);
  const params = parseQuery(query);

  password = password || params.password || params.auth || "";

  const sni = params.sni || params.peer || params.servername || "";
  const peer = params.peer || "";

  const insecureFlag =
    params.insecure ||
    params.allowInsecure ||
    params["skip-cert-verify"] ||
    "";

  const alpn = params.alpn || "";
  const clientFingerprint =
    params.fp ||
    params.fingerprint ||
    params["client-fingerprint"] ||
    "chrome";

  const udp =
    params.udp === undefined
      ? true
      : !["0", "false", "no"].includes(String(params.udp).toLowerCase());

  if (!server || !port || !password) {
    return {
      type: "anytls",
      raw,
      name: nameFromHash || raw,
      server,
      port,
      password,
      sni,
      peer,
      alpn,
      clientFingerprint,
      udp,
      skipCertVerify: parseBool(insecureFlag),
    };
  }

  return {
    type: "anytls",
    raw,
    name: nameFromHash || `${server}:${port}`,
    server,
    port,
    password,
    sni,
    peer,
    alpn,
    clientFingerprint,
    udp,
    skipCertVerify: parseBool(insecureFlag),
  };
}
