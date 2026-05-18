/*
 * functions/autosub/shared/utils/tuic.js
 *
 * TUIC URI 解析器
 *
 * 常见格式：
 * tuic://uuid:password@example.com:443?sni=example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native#Name
 * tuic://uuid:password@example.com:443?password=xxx&sni=example.com#Name
 * tuic://example.com:443?uuid=xxx&password=xxx&sni=example.com#Name
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

function normalizeChoice(value, allowed, fallback = "") {
  const s = String(value || "").trim().toLowerCase().replace(/_/g, "-");
  if (!s) return fallback;
  return allowed.includes(s) ? s : fallback;
}

function parseAlpn(v) {
  const s = String(v || "").trim();
  if (!s) return [];
  return s
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

export function parseTuic(input) {
  if (!input || typeof input !== "string") return null;

  const raw = input.trim();
  if (!raw.toLowerCase().startsWith("tuic://")) return null;

  let url;
  try {
    // URL 可以直接解析 tuic://
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
    (url.hash || "").replace(/^#/, "") ||
      url.hostname ||
      "TUIC"
  );

  const server = url.hostname.replace(/^\[|\]$/g, "");
  const port = Number(url.port || 443);

  /*
   * 常见 URI:
   * tuic://uuid:password@host:port?...
   *
   * url.username = uuid
   * url.password = password
   *
   * 也兼容：
   * ?uuid=xxx&password=xxx
   * ?token=xxx
   */
  const uuid =
    safeDecode(url.username) ||
    params.get("uuid") ||
    params.get("id") ||
    "";

  const password =
    safeDecode(url.password) ||
    params.get("password") ||
    params.get("pwd") ||
    params.get("token") ||
    "";

  const token = params.get("token") || "";

  const sni =
    params.get("sni") ||
    params.get("peer") ||
    params.get("servername") ||
    params.get("server_name") ||
    params.get("tls-host") ||
    "";

  const alpn = parseAlpn(params.get("alpn") || "h3");

  const congestionController = normalizeChoice(
    params.get("congestion_control") ||
      params.get("congestion-controller") ||
      params.get("cc") ||
      params.get("mode"),
    ["bbr", "cubic", "new-reno", "new_reno"],
    "bbr"
  ).replace(/_/g, "-");

  const udpRelayMode = normalizeChoice(
    params.get("udp_relay_mode") ||
      params.get("udp-relay-mode") ||
      params.get("udpRelayMode"),
    ["native", "quic"],
    "native"
  );

  const skipCertVerify = parseBool(
    params.get("insecure") ||
      params.get("allowInsecure") ||
      params.get("skip-cert-verify")
  );

  const reduceRtt = parseBool(
    params.get("reduce_rtt") ||
      params.get("reduce-rtt") ||
      params.get("0rtt") ||
      params.get("zero_rtt_handshake")
  );

  const disableSni = parseBool(
    params.get("disable_sni") || params.get("disable-sni")
  );

  const requestTimeout = Number(
    params.get("request_timeout") ||
      params.get("request-timeout") ||
      0
  );

  const heartbeatInterval = Number(
    params.get("heartbeat_interval") ||
      params.get("heartbeat-interval") ||
      0
  );

  const maxUdpRelayPacketSize = Number(
    params.get("max_udp_relay_packet_size") ||
      params.get("max-udp-relay-packet-size") ||
      0
  );

  const ip = params.get("ip") || "";

  return {
    type: "tuic",
    raw,
    name,
    server,
    port,
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
    heartbeatInterval: Number.isFinite(heartbeatInterval)
      ? heartbeatInterval
      : 0,
    maxUdpRelayPacketSize: Number.isFinite(maxUdpRelayPacketSize)
      ? maxUdpRelayPacketSize
      : 0,
    ip,
    udp: true,
  };
}