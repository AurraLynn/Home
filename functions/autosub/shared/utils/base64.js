export function safeB64Decode(str = "") {
    try {
        let s = (str || "").trim();
        if (!s) return "";

        s = s.replace(/-/g, "+").replace(/_/g, "/");
        const pad = s.length % 4;
        if (pad) s += "=".repeat(4 - pad);

        return atob(s);
    } catch {
        return "";
    }
}

export function safeB64Encode(str = "") {
    try {
        return btoa(str);
    } catch {
        return "";
    }
}