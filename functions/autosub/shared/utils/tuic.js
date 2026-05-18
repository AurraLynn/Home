/*
 * 文件路径：functions/autosub/shared/utils/tuic.js
 * 文件作用：
 *   - 解析 tuic:// 分享链接为 autosub 标准 Node
 *   - 兼容 TUIC v5 常见 URI 参数写法
 *
 * 常见格式：
 *   tuic://uuid:password@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#Name
 *   tuic://uuid:password@example.com:443?password=xxx&sni=example.com#Name
 *   tuic://example.com:443?uuid=xxx&password=xxx&sni=example.com#Name
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
  return s === "1" || s === "true" || s === "yes" || s === "on";
}

function normalizeKebab(v) {
  return String(v || "").trim().toLowerCase().replace(/_/g, "-");
}

function parseAlpn(v) {
  const s = String(v || "").trim();
  if (!s) return [];
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function pickParam(params, names, fallback = "") {
  for (const name of names) {
    const v = params.get(name);
    if (v !== null && v !== undefined && String(v).trim() !== "") return v;
  }
  return fallback;
}

export function parseTuic(input) {
  if (!input || typeof input !== "string") return null;

  const raw = input.trim();
  if (!raw.toLowerCase().startsWith("tuic://")) return null;

  let url;
  try {
    url = new URL(raw);
  } catch {
    return {
      type: "tuic",
      raw,
      name: raw,
    };
  }

  const params = url.searchParams;

  const name = safeDecode(
    (url.hash || "").replace(/^#/, "") || url.hostname || "TUIC"
  );

  const server = url.hostname.replace(/^\[|\]$/g, "");
  const port = Number(url.port || 443);

  // 标准常见：tuic://uuid:password@host:port?...#name
  // 兼容：?uuid=xxx&password=xxx 或 ?token=xxx
  const uuid =
    safeDecode(url.username) ||
    pickParam(params, ["uuid", "id", "user", "username"], "");

  const password =
    safeDecode(url.password) ||
    pickParam(params, ["password", "pwd", "pass"], "");

  const token = pickParam(params, ["token"], "");

  const sni = pickParam(
    params,
    ["sni", "peer", "servername", "server_name", "server-name", "tls-host"],
    ""
  );

  const alpn = parseAlpn(pickParam(params, ["alpn"], "h3"));

  const congestionController = normalizeKebab(
    pickParam(
      params,
      [
        "congestion_control",
        "congestion-controller",
        "congestion-control",
        "congestionController",
        "cc",
      ],
      "bbr"
    )
  );

  const udpRelayMode = normalizeKebab(
    pickParam(
      params,
      ["udp_relay_mode", "udp-relay-mode", "udpRelayMode"],
      "native"
    )
  );

  const skipCertVerify = parseBool(
    pickParam(
      params,
      [
        "insecure",
        "allowInsecure",
        "allow_insecure",
        "allow-insecure",
        "skip-cert-verify",
        "skip_cert_verify",
      ],
      ""
    )
  );

  const reduceRtt = parseBool(
    pickParam(
      params,
      ["reduce_rtt", "reduce-rtt", "0rtt", "zero_rtt_handshake"],
      ""
    )
  );

  const disableSni = parseBool(
    pickParam(params, ["disable_sni", "disable-sni", "disableSni"], "")
  );

  const requestTimeout = Number(
    pickParam(params, ["request_timeout", "request-timeout"], "0")
  );

  const heartbeatInterval = Number(
    pickParam(params, ["heartbeat_interval", "heartbeat-interval"], "0")
  );

  const maxUdpRelayPacketSize = Number(
    pickParam(
      params,
      ["max_udp_relay_packet_size", "max-udp-relay-packet-size"],
      "0"
    )
  );

  const ip = pickParam(params, ["ip"], "");

  return {
    type: "tuic",
    raw,
    name,
    server,
    port: Number.isFinite(port) && port > 0 ? port : 443,
    uuid,
    password,
    token,
    sni,
    alpn,
    congestionController,
    udpRelayMode,
    skipCertVerify,
    reduceRtt,
    disableSni,
    requestTimeout: Number.isFinite(requestTimeout) ? requestTimeout : 0,
    heartbeatInterval: Number.isFinite(heartbeatInterval) ? heartbeatInterval : 0,
    maxUdpRelayPacketSize: Number.isFinite(maxUdpRelayPacketSize)
      ? maxUdpRelayPacketSize
      : 0,
    ip,
    udp: true,
  };
}
