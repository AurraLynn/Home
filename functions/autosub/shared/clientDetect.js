function detectFromQuery(url) {
    const p =
        (url.searchParams.get("client") ||
            url.searchParams.get("target") ||
            url.searchParams.get("flag") ||
            url.searchParams.get("type") ||
            "").toLowerCase();

    if (!p) return "";

    if (["clash", "meta", "mihomo"].includes(p)) return "clash";
    if (p === "surge") return "surge";
    if (["qx", "quantumultx", "quantumult-x"].includes(p)) return "qx";
    if (p === "stash") return "stash";
    if (["v2ray", "base64"].includes(p)) return "v2ray";

    return "";
}

function detectFromUA(request) {
    const ua = (request.headers.get("user-agent") || "").toLowerCase();

    if (ua.includes("surge")) return "surge";
    if (ua.includes("stash")) return "stash";
    if (ua.includes("quantumult x") || ua.includes("quantumultx") || ua.includes("qx")) return "qx";
    if (ua.includes("clash") || ua.includes("mihomo") || ua.includes("clash meta") || ua.includes("clash-verge")) {
        return "clash";
    }

    return "";
}

export function detectClient(request) {
    const url = new URL(request.url);

    const q = detectFromQuery(url);
    if (q) return q;

    const u = detectFromUA(request);
    if (u) return u;

    // ✅ 识别不到默认 V2Ray(Base64)
    return "v2ray";
}1