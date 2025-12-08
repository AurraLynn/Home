export function splitLines(text = "") {
    return (text || "")
        .replace(/\r\n/g, "\n")
        .replace(/\r/g, "\n")
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
}

export function looksLikeBase64Subscription(text = "") {
    const s = (text || "").trim();
    if (!s) return false;
    if (/(ss|ssr|vmess|vless|trojan|hysteria):\/\//i.test(s)) return false;
    if (s.length < 40) return false;
    return /^[A-Za-z0-9\-_+/=]+$/.test(s);
}