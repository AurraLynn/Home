/* shared/utils/vless.js
 * VLESS 解析：
 *   - 支持：
 *       vless://uuid@host:port?encryption=none&security=tls&type=ws&host=xxx&path=/xxx&flow=xtls-rprx-vision&fp=chrome&sni=xxx#name
 */

function safeDecode(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}

export function parseVless(input) {
    if (!input) return null;
    const raw = String(input).trim();
    if (!raw.toLowerCase().startsWith("vless://")) return null;

    // 1. 拆 #name
    let nameFromHash = "";
    let main = raw;
    const hashIndex = raw.indexOf("#");
    if (hashIndex >= 0) {
        const hashPart = raw.slice(hashIndex + 1);
        nameFromHash = safeDecode(hashPart);
        main = raw.slice(0, hashIndex);
    }

    const name = nameFromHash || "";

    // 2. 去掉 vless://
    main = main.replace(/^vless:\/\//i, "");

    // 3. 拆 basePart?query
    let basePart = main;
    let query = "";
    const qIndex = main.indexOf("?");
    if (qIndex >= 0) {
        basePart = main.slice(0, qIndex);
        query = main.slice(qIndex + 1);
    }

    // 4. 解析 query 参数
    const params = {};
    if (query) {
        const segs = query.split("&");
        for (const seg of segs) {
            if (!seg) continue;
            const [kRaw, vRaw = ""] = seg.split("=", 2);
            const k = (kRaw || "").trim();
            if (!k) continue;
            const v = safeDecode((vRaw || "").trim());
            params[k] = v;
        }
    }

    // 5. 解析 basePart：uuid@host:port
    let uuid = "";
    let server = "";
    let port = 0;

    const atIndex = basePart.lastIndexOf("@");
    if (atIndex >= 0) {
        const idPart = basePart.slice(0, atIndex);
        const hostPortPart = basePart.slice(atIndex + 1);

        uuid = idPart.trim();

        const lastColon = hostPortPart.lastIndexOf(":");
        if (lastColon >= 0) {
            const serverRaw = hostPortPart.slice(0, lastColon);
            const portStr = hostPortPart.slice(lastColon + 1);
            server = (serverRaw || "").trim();
            port = Number((portStr || "").trim() || 0);
        } else {
            server = (hostPortPart || "").trim();
            port = 0;
        }
    }

    // 6. query 兜底
    if (!uuid) {
        uuid =
            (params.id ||
                params.uuid ||
                params.user ||
                params.uid ||
                "").toString().trim();
    }

    if (!server) {
        server =
            (params.host ||
                params.address ||
                params.add ||
                params.server ||
                params.servername ||
                "").toString().trim();
    }

    if (!port) {
        const pStr = (
            params.port ||
            params.server_port ||
            params.local_port ||
            ""
        )
            .toString()
            .trim();
        const p = Number(pStr || "0");
        if (p > 0) port = p;
    }

    // 7. 其它参数
    const encryption = (params.encryption || "none").toString().trim();

    let security = (params.security || params.tls || "").toString().trim();
    security = security.toLowerCase();

    let tls = false;
    if (["tls", "reality", "xtls"].includes(security)) {
        tls = true;
    }

    const sni = (
        params.sni ||
        params.peer ||
        params.servername ||
        params.host ||
        ""
    )
        .toString()
        .trim();

    const netRaw = (params.type || params.network || "").toString().trim();
    const network = netRaw ? netRaw.toLowerCase() : "tcp";

    const host = (
        params.host ||
        params.authority ||
        ""
    )
        .toString()
        .trim();

    let path = (
        params.path ||
        params.serviceName ||
        params["service-name"] ||
        ""
    )
        .toString()
        .trim();
    if (!path && network === "ws") path = "/";

    const flow = (params.flow || "").toString().trim();

    let udp = true;
    if (params.udp !== undefined) {
        const u = params.udp.toString().toLowerCase();
        if (["0", "false", "no"].includes(u)) udp = false;
    }

    const alpn = (params.alpn || "").toString().trim();
    const clientFingerprint =
        (params.fp || params.fingerprint || "").toString().trim();

    const realityPublicKey =
        (
            params.pbk ||
            params.publicKey ||
            params["public-key"] ||
            ""
        )
            .toString()
            .trim();

    const realityShortId =
        (
            params.sid ||
            params.shortId ||
            params["short-id"] ||
            ""
        )
            .toString()
            .trim();

    const realitySpiderX =
        (
            params.spx ||
            params.spiderX ||
            params["spider-x"] ||
            ""
        )
            .toString()
            .trim();

    if (!server || !port || !uuid) {
        return {
            type: "vless",
            raw,
            name: name || raw,
            encryption,
            security,
            tls,
            sni,
            network,
            host,
            path,
            flow,
            udp,
            alpn,
            clientFingerprint,
            realityPublicKey,
            realityShortId,
            realitySpiderX,
        };
    }

    return {
        type: "vless",
        raw,
        name: name || `${server}:${port}`,
        server,
        port,
        uuid,
        encryption,
        security,
        tls,
        sni,
        network,
        host,
        path,
        flow,
        udp,
        alpn,
        clientFingerprint,
        realityPublicKey,
        realityShortId,
        realitySpiderX,
    };
}