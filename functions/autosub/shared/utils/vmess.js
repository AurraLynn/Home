/* shared/utils/vmess.js
 * VMess 解析：
 *   - 支持：
 *       1) vmess://BASE64(JSON)
 *       2) vmess://[auto:]uuid@host:port?encryption=auto&security=tls&type=ws&host=xxx&path=/xxx#name
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

function parseQuery(search) {
    const out = {};
    if (!search) return out;
    const q = String(search).replace(/^\?+/, "");
    for (const part of q.split("&")) {
        if (!part) continue;
        const [kRaw, vRaw = ""] = part.split("=", 2);
        const k = (kRaw || "").trim();
        if (!k) continue;
        out[k] = safeDecodeURIComponent((vRaw || "").trim());
    }
    return out;
}

export function parseVmess(input) {
    try {
        if (!input) return null;
        const raw = String(input).trim();
        if (!raw.toLowerCase().startsWith("vmess://")) return null;

        // 拆 #name
        let nameFromHash = "";
        let main = raw;
        const hashIndex = raw.indexOf("#");
        if (hashIndex >= 0) {
            const hashPart = raw.slice(hashIndex + 1);
            nameFromHash = safeDecodeURIComponent(hashPart);
            main = raw.slice(0, hashIndex);
        }

        // 去掉前缀
        main = main.replace(/^vmess:\/\//i, "");

        // 优先尝试 JSON 形式（大部分机场）
        const decoded = safeBase64Decode(main);
        if (decoded && decoded.trim().startsWith("{")) {
            const obj = JSON.parse(decoded);

            const server =
                obj.add || obj.server || obj.address || obj.host || "";
            const port = Number(obj.port || obj.server_port || 0);
            const uuid = obj.id || obj.uuid || "";
            const security = obj.security || obj.encryption || "auto";
            const net = (obj.net || obj.network || "tcp").toLowerCase();
            const tls = String(obj.tls || "").toLowerCase() === "tls";
            const sni =
                obj.sni || obj.host || obj.servername || obj.peer || "";
            const host = obj.host || "";
            const path =
                obj.path ||
                obj["ws-path"] ||
                "";

            let name =
                obj.ps ||
                obj.name ||
                obj.remarks ||
                nameFromHash ||
                (server && port ? `${server}:${port}` : "");

            return {
                type: "vmess",
                raw,
                name: name || "",
                server,
                port,
                uuid,
                alterId: Number(obj.aid || obj.alterId || 0),
                security,
                network: net,
                tls,
                sni,
                host,
                path,
                alpn: obj.alpn || "",
                udp: obj.udp !== false,
            };
        }

        // 老式 URL 形式：vmess://[auto:]uuid@host:port?xxx
        let basePart = main;
        let search = "";
        const qIndex = main.indexOf("?");
        if (qIndex >= 0) {
            basePart = main.slice(0, qIndex);
            search = main.slice(qIndex);
        }

        const params = parseQuery(search);

        const atIndex = basePart.lastIndexOf("@");
        if (atIndex < 0) return null;

        const userPart = basePart.slice(0, atIndex);
        const hostPort = basePart.slice(atIndex + 1);

        let uuid = "";
        const colonIdx = userPart.indexOf(":");
        if (colonIdx >= 0) {
            uuid = userPart.slice(colonIdx + 1);
        } else {
            uuid = userPart;
        }

        const lastColon = hostPort.lastIndexOf(":");
        if (lastColon < 0) return null;
        const server = hostPort.slice(0, lastColon);
        const port = Number(hostPort.slice(lastColon + 1));

        const encryption =
            params.encryption || params.security || "auto";
        const security = params.security || "";
        const net = (params.type || params.network || "tcp").toLowerCase();
        const tls =
            security.toLowerCase() === "tls" ||
            security.toLowerCase() === "reality";

        const sni =
            params.sni ||
            params.peer ||
            params.servername ||
            params.host ||
            "";
        const host =
            params.host ||
            params.authority ||
            "";
        let path =
            params.path ||
            params["ws-path"] ||
            "";
        if (!path && net === "ws") path = "/";

        let name =
            nameFromHash ||
            params.remarks ||
            (server && port ? `${server}:${port}` : "");

        return {
            type: "vmess",
            raw,
            name: name || "",
            server: server.trim(),
            port,
            uuid: uuid.trim(),
            encryption,
            security,
            network: net,
            tls,
            sni,
            host,
            path,
            udp: params.udp !== "0",
            alpn: params.alpn || "",
        };
    } catch {
        return null;
    }
}