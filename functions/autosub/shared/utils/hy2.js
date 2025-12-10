/* shared/utils/hy2.js
 * Hysteria2 / hy2 / hysteria 解析：
 *   - hysteria2://password@host:port?peer=xxx&up=10&down=100&alpn=h3&insecure=1#name
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

export function parseHy2(input) {
    try {
        if (!input) return null;
        const raw = String(input).trim();
        const lower = raw.toLowerCase();
        if (
            !(
                lower.startsWith("hysteria2://") ||
                lower.startsWith("hy2://") ||
                lower.startsWith("hysteria://")
            )
        ) {
            return null;
        }

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
        main = main.replace(/^hysteria2:\/\//i, "");
        main = main.replace(/^hy2:\/\//i, "");
        main = main.replace(/^hysteria:\/\//i, "");

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

        const pwd = basePart.slice(0, atIndex).trim();
        const hostPort = basePart.slice(atIndex + 1);
        const lastColon = hostPort.lastIndexOf(":");
        if (lastColon < 0) return null;

        const server = hostPort.slice(0, lastColon).trim();
        const port = Number(hostPort.slice(lastColon + 1));

        if (!server || !port || !pwd) {
            return {
                type: "hysteria2",
                raw,
                name: nameFromHash || raw,
            };
        }

        const up =
            params.upmbps ||
            params.up ||
            "";
        const down =
            params.downmbps ||
            params.down ||
            "";

        const sni =
            params.sni ||
            params.peer ||
            params.servername ||
            "";

        const skipCertVerify =
            params.insecure === "1" ||
            params.allowInsecure === "1" ||
            params["skip-cert-verify"] === "1";

        const ports =
            params.ports ||
            params.mport ||
            "";

        const obfs = params.obfs || "";
        const obfsPassword =
            params["obfs-password"] ||
            params.obfsParam ||
            "";

        return {
            type: "hysteria2",
            raw,
            name: nameFromHash || `${server}:${port}`,
            server,
            port,
            password: pwd,
            auth: pwd,
            sni,
            peer: params.peer || "",
            alpn: params.alpn || "",
            upmbps: up,
            downmbps: down,
            ports,
            udp: params.udp !== "0",
            skipCertVerify,
            obfs,
            obfsPassword,
        };
    } catch {
        return null;
    }
}