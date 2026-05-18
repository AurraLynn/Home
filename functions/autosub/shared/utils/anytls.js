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

function safeDecode(value) {
    try {
        return decodeURIComponent(String(value || ""));
    } catch {
        return String(value || "");
    }
}

function parseBool(value) {
    const v = String(value ?? "").trim().toLowerCase();
    return v === "1" || v === "true" || v === "yes" || v === "on";
}

function parseAlpn(value) {
    const raw = String(value || "").trim();
    if (!raw) return "";
    return raw
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean)
        .join(",");
}

export function parseAnyTLS(input) {
    if (!input || typeof input !== "string") return null;

    const raw = input.trim();
    if (!raw.toLowerCase().startsWith("anytls://")) return null;

    let url;
    try {
        url = new URL(raw);
    } catch {
        return {
            type: "anytls",
            raw,
            name: raw,
        };
    }

    const params = url.searchParams;

    const name =
        safeDecode((url.hash || "").replace(/^#/, "")) ||
        url.hostname ||
        "AnyTLS";

    const password =
        safeDecode(url.username || "") ||
        safeDecode(params.get("password") || "") ||
        safeDecode(params.get("auth") || "");

    const server = (url.hostname || "").replace(/^\[|\]$/g, "");
    const port = Number(url.port || params.get("port") || 443) || 443;

    const sni =
        params.get("sni") ||
        params.get("peer") ||
        params.get("servername") ||
        params.get("serverName") ||
        "";

    const insecure =
        params.get("insecure") ??
        params.get("allowInsecure") ??
        params.get("skip-cert-verify") ??
        "";

    const clientFingerprint =
        params.get("client-fingerprint") ||
        params.get("fingerprint") ||
        params.get("fp") ||
        "chrome";

    const udpRaw = params.get("udp");
    const udp =
        udpRaw === null
            ? true
            : !["0", "false", "no", "off"].includes(
                  String(udpRaw).trim().toLowerCase()
              );

    return {
        type: "anytls",
        raw,
        name,
        server,
        port,
        password,
        sni,
        peer: params.get("peer") || "",
        alpn: parseAlpn(params.get("alpn")),
        clientFingerprint,
        udp,
        skipCertVerify: parseBool(insecure),
    };
}
