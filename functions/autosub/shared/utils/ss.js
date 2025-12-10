/* shared/utils/ss.js
 * Shadowsocks 解析：
 *   - 支持：
 *       1) ss://BASE64(method:password@host:port)#name
 *       2) ss://BASE64(method:password)@host:port#name
 *       3) ss://method:password@host:port#name
 *   - 输出 Node：
 *       {
 *         type: "ss",
 *         name,
 *         server,
 *         port,
 *         cipher,
 *         password,
 *         plugin?,       // 原始 plugin 名
 *         pluginOpts?,   // 原始 plugin 参数串
 *         raw
 *       }
 */

function safeDecodeURIComponent(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}

function safeBase64Decode(str) {
    try {
        const s = String(str || "").replace(/\s+/g, "");
        if (!s) return "";
        let norm = s.replace(/-/g, "+").replace(/_/g, "/");
        const pad = norm.length % 4;
        if (pad === 2) norm += "==";
        else if (pad === 3) norm += "=";
        else if (pad === 1) norm += "===";

        return decodeURIComponent(
            escape(atob(norm)),
        );
    } catch {
        return "";
    }
}

/* 解析 plugin=xxx;mode=xx;host=xx 之类 */
function parsePlugin(search) {
    if (!search) return null;
    const q = String(search).replace(/^\?+/, "");
    const match = q.match(/(?:^|&)plugin=([^&]+)/i);
    if (!match || !match[1]) return null;

    let pluginRaw = match[1];
    pluginRaw = safeDecodeURIComponent(pluginRaw);

    const parts = pluginRaw.split(";").filter(Boolean);
    if (!parts.length) return null;

    const [pluginName, ...rest] = parts;
    const opts = rest.join(";");

    return {
        plugin: pluginName,
        pluginOpts: opts,
    };
}

export function parseSS(input) {
    try {
        if (!input) return null;
        const raw = String(input).trim();
        if (!raw.toLowerCase().startsWith("ss://")) return null;

        // 1) 拆 #name
        let name = "";
        let main = raw;
        const hashIndex = raw.indexOf("#");
        if (hashIndex >= 0) {
            const hashPart = raw.slice(hashIndex + 1);
            name = safeDecodeURIComponent(hashPart);
            main = raw.slice(0, hashIndex);
        }

        // 2) 去掉 ss://
        main = main.replace(/^ss:\/\//i, "");

        // 3) 拆 ?plugin=...
        let base = main;
        let search = "";
        const qIndex = main.indexOf("?");
        if (qIndex >= 0) {
            base = main.slice(0, qIndex);
            search = main.slice(qIndex);
        }

        let method = "";
        let password = "";
        let server = "";
        let port = 0;

        if (base.includes("@")) {
            // 可能是 “BASE64(method:password)@host:port” 或 “明文 method:password@host:port”
            const atIndex = base.lastIndexOf("@");
            const userPart = base.slice(0, atIndex);
            const hostPort = base.slice(atIndex + 1);

            // userPart 可能是 base64，也可能是明文
            if (/^[A-Za-z0-9+/=_-]+$/.test(userPart) && !userPart.includes(":")) {
                const decodedUser = safeBase64Decode(userPart);
                const idx2 = decodedUser.indexOf(":");
                if (idx2 < 0) return null;
                method = decodedUser.slice(0, idx2);
                password = decodedUser.slice(idx2 + 1);
            } else {
                const idx2 = userPart.indexOf(":");
                if (idx2 < 0) return null;
                method = userPart.slice(0, idx2);
                password = userPart.slice(idx2 + 1);
            }

            const lastColon = hostPort.lastIndexOf(":");
            if (lastColon < 0) return null;
            server = hostPort.slice(0, lastColon);
            port = Number(hostPort.slice(lastColon + 1));
        } else {
            // 整块 base 是 base64(method:password@host:port)
            const decoded = safeBase64Decode(base);
            const atIndex = decoded.lastIndexOf("@");
            if (atIndex < 0) return null;
            const userPart = decoded.slice(0, atIndex);
            const hostPort = decoded.slice(atIndex + 1);
            const idx2 = userPart.indexOf(":");
            if (idx2 < 0) return null;
            method = userPart.slice(0, idx2);
            password = userPart.slice(idx2 + 1);

            const lastColon = hostPort.lastIndexOf(":");
            if (lastColon < 0) return null;
            server = hostPort.slice(0, lastColon);
            port = Number(hostPort.slice(lastColon + 1));
        }

        method = method.trim();
        password = password.trim();
        server = server.trim();
        if (!method || !password || !server || !port) return null;

        let plugin;
        let pluginOpts;
        if (search) {
            const parsed = parsePlugin(search);
            if (parsed) {
                plugin = parsed.plugin;
                pluginOpts = parsed.pluginOpts;
            }
        }

        return {
            type: "ss",
            name: name || `${server}:${port}`,
            server,
            port,
            cipher: method,
            password,
            ...(plugin ? { plugin } : {}),
            ...(pluginOpts ? { pluginOpts } : {}),
            raw: raw,
        };
    } catch {
        return null;
    }
}