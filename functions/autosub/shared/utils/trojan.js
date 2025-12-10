/* shared/utils/trojan.js
 * Trojan 解析：
 *   - trojan://password@host:port?peer=xxx&sni=xxx&security=tls&type=ws&path=/xxx#name
 */

function safeDecode(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
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
        out[k] = safeDecode((vRaw || "").trim());
    }
    return out;
}

export function parseTrojan(input) {
    try {
        if (!input) return null;
        const raw = String(input).trim();
        if (!raw.toLowerCase().startsWith("trojan://")) return null;

        // 1) 拆 #name
        let nameFromHash = "";
        let main = raw;
        const hashIndex = raw.indexOf("#");
        if (hashIndex >= 0) {
            const hashPart = raw.slice(hashIndex + 1);
            nameFromHash = safeDecode(hashPart);
            main = raw.slice(0, hashIndex);
        }

        // 2) 去掉前缀
        main = main.replace(/^trojan:\/\//i, "");

        // 3) 拆 ?query
        let basePart = main;
        let search = "";
        const qIndex = main.indexOf("?");
        if (qIndex >= 0) {
            basePart = main.slice(0, qIndex);
            search = main.slice(qIndex);
        }

        const params = parseQuery(search);

        // 4) password@host:port
        const atIndex = basePart.lastIndexOf("@");
        if (atIndex < 0) return null;

        const password = basePart.slice(0, atIndex).trim();
        const hostPort = basePart.slice(atIndex + 1);

        const lastColon = hostPort.lastIndexOf(":");
        if (lastColon < 0) return null;

        const server = hostPort.slice(0, lastColon).trim();
        const port = Number(hostPort.slice(lastColon + 1));

        if (!server || !port || !password) {
            return {
                type: "trojan",
                raw,
                name: nameFromHash || raw,
                sni: params.sni || params.peer || "",
            };
        }

        const security = (params.security || "").toString().toLowerCase();
        const tls =
            security === "tls" || security === "reality" || security === "";

        const sni =
            params.sni ||
            params.peer ||
            params.servername ||
            params.host ||
            "";

        const net = (
            params.type ||
            params.network ||
            ""
        )
            .toString()
            .trim()
            .toLowerCase();

        const host =
            params.host ||
            params.authority ||
            "";
        const path =
            params.path ||
            params["ws-path"] ||
            "";
        const alpn = params.alpn || "";

        return {
            type: "trojan",
            raw,
            name: nameFromHash || `${server}:${port}`,
            server,
            port,
            password,
            security,
            tls,
            sni,
            network: net,
            host,
            path,
            udp: params.udp !== "0",
            alpn,
        };
    } catch {
        return null;
    }
}