/*
 * 文件路径：functions/autosub/shared/utils/vless.js
 * 文件作用：
 *   - 解析 VLESS 节点为标准 Node 对象
 *   - 支持 Reality / XTLS / base64 userinfo / obfs(websocket/grpc) 等多种写法
 *   - 尽量还原 uuid/server/port 及 pbk/sid/flow/sni/host/path 等高级参数
 */

function safeDecode(str) {
    try {
        return decodeURIComponent(str);
    } catch {
        return str;
    }
}

/*
 * 工具函数：拆分 host:port
 *   - 使用最后一个冒号区分主机与端口，兼容 IPv6 场景
 */
function splitHostPort(str) {
    const s = (str || "").trim();
    if (!s) return ["", 0];

    const lastColon = s.lastIndexOf(":");
    if (lastColon < 0) {
        return [s, 0];
    }

    const host = s.slice(0, lastColon).trim();
    const portStr = s.slice(lastColon + 1).trim();
    const portNum = portStr ? Number(portStr) || 0 : 0;

    return [host, portNum];
}

/*
 * 工具函数：尝试将 basePart 当做 base64 解码
 *   - 用于兼容 vless://BASE64?xxx 这种写法（BASE64 → "method:uuid@host:port"）
 */
function tryDecodeBase64UserInfo(basePart) {
    const raw = (basePart || "").trim();
    if (!raw) return "";

    // 尝试 url-safe → 普通 base64
    const b64 = raw.replace(/-/g, "+").replace(/_/g, "/");

    // 粗略判断是不是 base64
    if (!/^[A-Za-z0-9+/=]+$/.test(b64)) return "";

    try {
        const decoded = atob(b64);
        return decoded || "";
    } catch {
        return "";
    }
}

/*
 * 主函数：parseVless
 *
 * 功能：
 *   - 解析 vless://... 链接为标准 Node 对象
 *   - 支持：
 *       • 标准写法：vless://uuid@host:port?...#name
 *       • base64 userinfo：vless://BASE64?remarks=...&tls=1&peer=...&pbk=...&sid=...
 *       • Reality / XTLS：security=reality / pbk / sid / xtls / flow
 *       • 传输方式：type/network 或 obfs=websocket/grpc + obfsParam
 *   - 当 server/port/uuid 不完整时，也会返回“半成品”节点，方便调试
 */
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

    // 2. 去掉 vless://
    main = main.replace(/^vless:\/\//i, "");

    // 3. 拆 basePart ? query
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
            const key = safeDecode(k);
            const val = safeDecode(vRaw);
            params[key] = val;
        }
    }

    // 5. 从 basePart + params 还原 uuid / server / port

    let uuid = "";
    let server = "";
    let port = 0;
    let methodFromBase = "";

    let tmpBase = (basePart || "").trim();

    // 尝试先按 uuid@host:port 来拆
    let atIndex = tmpBase.lastIndexOf("@");

    // 如果根本没有 @，尝试当成 base64("method:uuid@host:port")
    if (atIndex < 0 && tmpBase) {
        const decoded = tryDecodeBase64UserInfo(tmpBase);
        if (decoded && decoded.includes("@")) {
            tmpBase = decoded.trim(); // 例如 "auto:uuid@host:443"
            atIndex = tmpBase.lastIndexOf("@");
        }
    }

    if (atIndex >= 0) {
        const idPart = tmpBase.slice(0, atIndex);
        const hostPortPart = tmpBase.slice(atIndex + 1);

        const idTrim = idPart.trim();
        const colonInId = idTrim.lastIndexOf(":");
        if (colonInId >= 0) {
            // 形如 "auto:uuid"
            methodFromBase = idTrim.slice(0, colonInId).trim();
            uuid = idTrim.slice(colonInId + 1).trim();
        } else {
            // 形如 "uuid"
            uuid = idTrim;
        }

        const [host, p] = splitHostPort(hostPortPart);
        server = host;
        port = p;
    } else if (tmpBase) {
        // 没有 @，可能是 host:port 写法，uuid 在 query 里
        const [host, p] = splitHostPort(tmpBase);
        server = host;
        port = p;
    }

    // uuid 从 query 兜底
    if (!uuid) {
        uuid =
            (params.id ||
                params.uuid ||
                params.userId ||
                params["user-id"] ||
                params["userId"] ||
                "") + "";
        uuid = uuid.trim();
    }

    // server / port 从 query 兜底
    if (!server && params.server) {
        server = (params.server || "").toString().trim();
    }

    if (!port && params.port) {
        const p = Number((params.port || "").toString().trim());
        if (!Number.isNaN(p)) port = p;
    }

    // 6. 其它字段整理

    // XTLS 模式（数字 / 文本都兼容）：常见为 1=direct, 2=vision
    const xtlsMode = (params.xtls || params.xtlsType || "").toString().trim();

    // obfs：很多节点用 obfs=websocket / obfsParam=host 表示 ws/grpc
    const obfs = (params.obfs || params.obfsType || "").toString().trim().toLowerCase();
    const obfsParam =
        (params.obfsParam || params["obfs-param"] || "").toString().trim();

    const name =
        (params.remarks ||
            params.remark ||
            nameFromHash ||
            params.ps ||
            params.name ||
            "") + "";

    let encryption =
        (params.encryption || methodFromBase || "none").toString().trim() || "none";

    let security = (params.security || "").toString().trim().toLowerCase();

    let tls = false;
    if (security === "tls" || security === "reality") {
        tls = true;
    } else if (params.tls !== undefined) {
        const t = params.tls.toString().toLowerCase();
        if (["1", "true", "tls"].includes(t)) {
            tls = true;
            if (!security) security = "tls";
        }
    }

    // 有些机场 Reality 会用 reality/xtls 字段
    if (!security && (params.reality || params.xtls)) {
        security = "reality";
        tls = true;
    }

    let sni =
        (params.sni ||
            params.peer ||
            params.servername ||
            params["server-name"] ||
            "") + "";
    sni = sni.toString().trim();

    // network：优先 type/network，其次 obfs
    let network =
        (params.type || params.network || "").toString().trim().toLowerCase();

    if (!network && obfs) {
        if (obfs === "ws" || obfs === "websocket") {
            network = "ws";
        } else if (obfs === "grpc" || obfs === "gun") {
            network = "grpc";
        }
    }

    if (!network) network = "tcp";
    if (network === "gun") network = "grpc";
    if (network === "websocket") network = "ws";

    const host =
        (params.host || params.headerTypeHost || obfsParam || "").toString().trim();

    const path =
        (params.path ||
            params.serviceName ||
            params["serviceName"] ||
            params["grpc-service-name"] ||
            "") + "";

    // flow：优先使用显式 flow，其次根据 xtlsMode 映射
    let flow = (params.flow || "").toString().trim();

    if (!flow && xtlsMode) {
        const m = xtlsMode.toLowerCase();

        // 数字编码：常见面板用 1=direct, 2=vision
        if (m === "1") {
            flow = "xtls-rprx-direct";
        } else if (m === "2") {
            flow = "xtls-rprx-vision";
        } else if (m === "3") {
            flow = "xtls-rprx-origin";
        } else if (m === "4") {
            flow = "xtls-rprx-splice";
        } else {
            // 文本兜底：兼容直接写字符串的情况
            if (m === "direct" || m === "xtls-rprx-direct") {
                flow = "xtls-rprx-direct";
            } else if (m === "vision" || m === "xtls-rprx-vision") {
                flow = "xtls-rprx-vision";
            } else if (m === "origin" || m === "xtls-rprx-origin") {
                flow = "xtls-rprx-origin";
            } else if (m === "splice" || m === "xtls-rprx-splice") {
                flow = "xtls-rprx-splice";
            }
        }
    }

    // udp：默认 true，0/false 关掉
    let udp = true;
    if (params.udp !== undefined) {
        const u = params.udp.toString().toLowerCase();
        if (["0", "false", "no"].includes(u)) udp = false;
    }

    const alpn = (params.alpn || "").toString().trim();

    const clientFingerprint =
        (params.fp || params.fingerprint || "").toString().trim();

    // Reality 相关
    const realityPublicKey =
        (params.pbk ||
            params["publicKey"] ||
            params["public-key"] ||
            "") + "";
    const realityShortId =
        (params.sid || params["shortId"] || params["short-id"] || "") + "";
    const realitySpiderX =
        (params.spx || params["spiderX"] || params["spider-x"] || "") + "";

    // 7. 不完整的也先返回“半成品”，方便调试
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
            realityPublicKey: realityPublicKey.trim(),
            realityShortId: realityShortId.trim(),
            realitySpiderX: realitySpiderX.trim(),
        };
    }

    // 8. 完整节点
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
        realityPublicKey: realityPublicKey.trim(),
        realityShortId: realityShortId.trim(),
        realitySpiderX: realitySpiderX.trim(),
    };
}
