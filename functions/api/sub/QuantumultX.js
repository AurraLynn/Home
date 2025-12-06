// functions/api/sub/QuantumultX.js
//
// 支持类型输入：
// -  URL格式
// -  URL/Base64 混合格式
// -  Base64（单条、多条、整条订阅）
//
// 支持协议输出（仅支持白名单列表）：
// -  Quantumult X：
//         Shadowsocks / UDP
//         Shadowsocks / HTTP / UDP
//         VLESS / UDP
//         TROJAN / UDP
//         VMESS / UDP
//         VMESS / WEBSOCKET / UDP
//         VMESS / HTTP / UDP
//
// client 行为：
// -  只处理 Quantumult X，供 /api/sub/Converter 调用
// -  不在白名单里的协议 / 传输方式一律丢弃，不下发给客户端

export async function onRequestPost(context) {
    const { request } = context;

    const rawText = await request.text();
    const text = (rawText || "").trim();
    if (!text) {
        return new Response("# empty input\n", {
            status: 200,
            headers: { "content-type": "text/plain; charset=utf-8" },
        });
    }

    const nodes = parseMixedInputToNodes(text);
    let out = "";

    if (!nodes.length) {
        out = "# no shadowsocks/vless/trojan/vmess nodes\n";
    } else {
        const outText = buildQuantumultXConfig(nodes);
        out = outText || "# no shadowsocks/vless/trojan/vmess nodes\n";
    }

    return new Response(out, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
    });
}

// ========== 通用解析：把混合输入拆成一行一行 URL / Base64 ==========

function parseMixedInputToNodes(text) {
    const lines = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => !!l && !l.startsWith("#") && !l.startsWith("//"));

    const nodes = [];

    for (const lineRaw of lines) {
        let line = lineRaw.trim();

        // Base64 纯订阅整段
        if (!line.includes("://") && /^[A-Za-z0-9+/=]+$/.test(line)) {
            const decoded = safeBase64Decode(line);
            if (!decoded) continue;

            const subLines = decoded
                .split(/\r?\n/)
                .map((l) => l.trim())
                .filter((l) => !!l && !l.startsWith("#") && !l.startsWith("//"));

            for (const sub of subLines) {
                const n = parseSingleUriToNode(sub);
                if (n) nodes.push(n);
            }
            continue;
        }

        // 正常 URL / URL+参数
        const n = parseSingleUriToNode(line);
        if (n) nodes.push(n);
    }

    return nodes;
}

// 单条 uri → node
function parseSingleUriToNode(uri) {
    if (!uri) return null;
    const u = uri.trim();

    if (u.startsWith("ss://")) {
        return parseShadowsocksLenient(u);
    }
    if (u.startsWith("vless://")) {
        return parseVlessLenient(u);
    }
    if (u.startsWith("trojan://")) {
        return parseTrojanLenient(u);
    }
    if (u.startsWith("vmess://")) {
        return parseVmessLenient(u);
    }

    return null;
}

function safeBase64Decode(b64) {
    if (!b64) return "";
    let s = b64.trim();
    // URL 安全 → 标准 Base64
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    // 补齐 =
    const pad = s.length % 4;
    if (pad === 2) s += "==";
    else if (pad === 3) s += "=";

    try {
        return atob(s);
    } catch (_e) {
        return "";
    }
}

// ========== Shadowsocks 解析：ss://... ==========

function parseShadowsocksLenient(uri) {
    try {
        let u = uri.replace(/^ss:\/\//i, "");

        // 先拆掉 #name
        let name = "";
        const hashIndex = u.indexOf("#");
        if (hashIndex !== -1) {
            const namePart = u.slice(hashIndex + 1);
            u = u.slice(0, hashIndex);
            if (namePart) {
                try {
                    name = decodeURIComponent(namePart);
                } catch (_e) {
                    name = namePart;
                }
            }
        }

        // 可能带 plugin= 参数
        let main = u;
        let queryStr = "";
        const qIndex = u.indexOf("?");
        if (qIndex !== -1) {
            main = u.slice(0, qIndex);
            queryStr = u.slice(qIndex + 1);
        }

        // 可能是完全 Base64，也可能是 method:password@host:port 形式
        let userinfoHostPort = "";
        const decoded = safeBase64Decode(main);
        if (decoded && decoded.includes("@")) {
            userinfoHostPort = decoded;
        } else {
            userinfoHostPort = main;
        }

        const atIndex = userinfoHostPort.lastIndexOf("@");
        if (atIndex === -1) {
            return null;
        }

        const userinfo = userinfoHostPort.slice(0, atIndex);
        const serverPart = userinfoHostPort.slice(atIndex + 1);

        let cipher = "";
        let password = "";

        if (userinfo && userinfo.includes(":")) {
            const idx = userinfo.indexOf(":");
            cipher = userinfo.slice(0, idx);
            password = userinfo.slice(idx + 1);
        }

        // serverPart 可能带 query
        let hostPortRaw = serverPart;
        let queryStr2 = queryStr;
        if (!queryStr2) {
            const q2 = serverPart.indexOf("?");
            if (q2 !== -1) {
                hostPortRaw = serverPart.slice(0, q2);
                queryStr2 = serverPart.slice(q2 + 1);
            }
        }

        let host = hostPortRaw;
        let port = 8388;
        const m = /:(\d+)$/.exec(hostPortRaw);
        if (m) {
            port = parseInt(m[1], 10) || 8388;
            host = hostPortRaw.slice(0, m.index);
        }

        // plugin / obfs
        let plugin = "";
        let pluginMode = "";
        let pluginHost = "";

        if (queryStr2) {
            const q = new URLSearchParams(queryStr2);

            const pluginParam = q.get("plugin") || "";
            if (pluginParam && pluginParam.includes("obfs-local")) {
                plugin = "obfs";

                pluginMode = q.get("obfs") || "";
                pluginHost = q.get("obfs-host")
                    ? decodeURIComponent(q.get("obfs-host"))
                    : "";

                if (!pluginMode) {
                    const mm = /obfs=([^;]+)/.exec(pluginParam);
                    if (mm) pluginMode = mm[1];
                }
                if (!pluginHost) {
                    const mh = /obfs-host=([^;]+)/.exec(pluginParam);
                    if (mh) pluginHost = decodeURIComponent(mh[1] || "");
                }
            }
        }

        if (!name) {
            name = `${host}:${port}`;
        }

        return {
            raw: uri,
            scheme: "ss",
            type: "ss",
            name,
            server: host,
            port,
            cipher,
            password,

            plugin,
            pluginMode,
            pluginHost,
        };
    } catch (_e) {
        return {
            raw: uri,
            scheme: "ss",
            type: "ss",
            name: uri,
        };
    }
}

// ========== VLESS 解析：vless://（只做 UDP 直连） ==========

function parseVlessLenient(uri) {
    try {
        let u = uri.replace(/^vless:\/\//i, "");

        // name
        let name = "";
        const hashIndex = u.indexOf("#");
        if (hashIndex !== -1) {
            const namePart = u.slice(hashIndex + 1);
            u = u.slice(0, hashIndex);
            if (namePart) {
                try {
                    name = decodeURIComponent(namePart);
                } catch (_e) {
                    name = namePart;
                }
            }
        }

        let main = u;
        let queryStr = "";
        const qIndex = u.indexOf("?");
        if (qIndex !== -1) {
            main = u.slice(0, qIndex);
            queryStr = u.slice(qIndex + 1);
        }

        const atIndex = main.lastIndexOf("@");
        if (atIndex === -1) {
            return null;
        }

        const userinfo = main.slice(0, atIndex);
        const hostPort = main.slice(atIndex + 1);

        const uuid = decodeURIComponentSafe(userinfo);

        let host = hostPort || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPort);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            host = hostPort.slice(0, m.index);
        }

        let tls = "";
        let sni = "";
        let path = "";

        if (queryStr) {
            const q = new URLSearchParams(queryStr);

            const r =
                q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
            if (r) {
                try {
                    name = decodeURIComponent(r);
                } catch (_e) {
                    name = r;
                }
            }

            if (q.get("tls") === "1" || q.get("security") === "tls") {
                tls = "tls";
            }
            const peer = q.get("peer") || q.get("sni") || "";
            if (peer) {
                sni = peer;
            }

            const p = q.get("path") || "";
            if (p) {
                path = p;
            }
        }

        return {
            raw: uri,
            scheme: "vless",
            type: "vless",

            name,
            server: host,
            port,
            uuid,
            encryption: "none",

            tls,
            sni,
            path,
        };
    } catch (_e) {
        return {
            raw: uri,
            scheme: "vless",
            type: "vless",
            name: uri,
            server: "0.0.0.0",
            port: 443,
            uuid: "",
            encryption: "none",
            tls: "",
            sni: "",
            path: "",
        };
    }
}

// ========== TROJAN 解析：trojan:// ==========

function parseTrojanLenient(uri) {
    try {
        let u = uri.replace(/^trojan:\/\//i, "");

        // name
        let name = "";
        const hashIndex = u.indexOf("#");
        if (hashIndex !== -1) {
            const namePart = u.slice(hashIndex + 1);
            u = u.slice(0, hashIndex);
            if (namePart) {
                try {
                    name = decodeURIComponent(namePart);
                } catch (_e) {
                    name = namePart;
                }
            }
        }

        let main = u;
        let queryStr = "";
        const qIndex = u.indexOf("?");
        if (qIndex !== -1) {
            main = u.slice(0, qIndex);
            queryStr = u.slice(qIndex + 1);
        }

        const atIndex = main.lastIndexOf("@");
        if (atIndex === -1) {
            return null;
        }

        const passwordPart = main.slice(0, atIndex);
        const hostPort = main.slice(atIndex + 1);

        const password = decodeURIComponentSafe(passwordPart);

        let host = hostPort || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPort);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            host = hostPort.slice(0, m.index);
        }

        let sni = "";
        let skipCertVerify = false;

        if (queryStr) {
            const q = new URLSearchParams(queryStr);

            const r =
                q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
            if (r) {
                try {
                    name = decodeURIComponent(r);
                } catch (_e) {
                    name = r;
                }
            }

            const peer = q.get("peer") || q.get("sni") || "";
            if (peer) {
                sni = peer;
            }

            const insecure = q.get("allowInsecure") || "";
            if (insecure === "1" || insecure === "true") {
                skipCertVerify = true;
            }
        }

        return {
            raw: uri,
            scheme: "trojan",
            type: "trojan",

            name,
            server: host,
            port,
            password,

            sni,
            skipCertVerify,
        };
    } catch (_e) {
        return {
            raw: uri,
            scheme: "trojan",
            type: "trojan",
            name: uri,
            server: "0.0.0.0",
            port: 443,
            password: "",
            sni: "",
            skipCertVerify: false,
        };
    }
}

// ========== VMESS 解析：vmess://（UDP / WS / HTTP） ========== */

function parseVmessLenient(uri) {
    try {
        let u = uri.replace(/^vmess:\/\//i, "");

        let main = u;
        let queryStr = "";
        const qIndex = u.indexOf("?");
        if (qIndex !== -1) {
            main = u.slice(0, qIndex);
            queryStr = u.slice(qIndex + 1);
        }

        let decoded = safeBase64Decode(main);
        let userinfoHostPort = "";

        if (decoded && decoded.includes("@") && decoded.includes(":")) {
            userinfoHostPort = decoded;
        } else {
            userinfoHostPort = main;
        }

        let name = "";
        const hashIndex = userinfoHostPort.indexOf("#");
        if (hashIndex !== -1) {
            const namePart = userinfoHostPort.slice(hashIndex + 1);
            userinfoHostPort = userinfoHostPort.slice(0, hashIndex);
            if (namePart) {
                try {
                    name = decodeURIComponent(namePart);
                } catch (_e) {
                    name = namePart;
                }
            }
        }

        const atIndex = userinfoHostPort.lastIndexOf("@");
        if (atIndex === -1) {
            return null;
        }

        const userinfo = userinfoHostPort.slice(0, atIndex);
        const hostPort = userinfoHostPort.slice(atIndex + 1);

        let uuid = "";
        if (userinfo.includes(":")) {
            const parts = userinfo.split(":");
            uuid = parts[parts.length - 1] || "";
        } else {
            uuid = userinfo;
        }

        let host = hostPort || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPort);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            host = hostPort.slice(0, m.index);
        }

        let obfs = "";
        let obfsHost = "";
        let obfsUri = "/";
        let tls = "";

        if (queryStr) {
            const q = new URLSearchParams(queryStr);

            const r =
                q.get("remarks") || q.get("name") || q.get("tag") || q.get("remark");
            if (r) {
                try {
                    name = decodeURIComponent(r);
                } catch (_e) {
                    name = r;
                }
            }

            const obfsType = q.get("obfs") || q.get("network") || "";

            const hostFrom = q.get("obfsParam") || q.get("host") || "";
            const path = q.get("path") || q.get("obfsUri") || "/";

            if (obfsType === "websocket" || obfsType === "ws") {
                obfs = "ws";
                obfsHost = hostFrom || host;
                obfsUri = path || "/";
            } else if (obfsType === "http") {
                obfs = "http";
                obfsHost = hostFrom || host;
                obfsUri = path || "/";
            }

            if (q.get("tls") === "1" || q.get("security") === "tls") {
                tls = "tls";
            }
        }

        return {
            raw: uri,
            scheme: "vmess",
            type: "vmess",

            name,
            server: host,
            port,
            uuid,
            encryption: "auto",

            obfs,
            obfsHost,
            obfsUri,
            tls,
        };
    } catch (_e) {
        return {
            raw: uri,
            scheme: "vmess",
            type: "vmess",
            name: uri,
            server: "0.0.0.0",
            port: 443,
            uuid: "",
            encryption: "auto",
            obfs: "",
            obfsHost: "",
            obfsUri: "/",
            tls: "",
        };
    }
}

// ========== 辅助：安全解码 ==========

function decodeURIComponentSafe(s) {
    if (!s) return "";
    try {
        return decodeURIComponent(s);
    } catch (_e) {
        return s;
    }
}

// ========== Quantumult X 白名单：仅下发以下协议 / 传输组合 ==========
//
// 形态 key 约定：
// - ss-udp
// - ss-http-udp
// - vless-udp
// - trojan-udp
// - vmess-udp
// - vmess-ws-udp
// - vmess-http-udp
const QX_ALLOWED_SHAPES = new Set([
    "ss-udp",
    "ss-http-udp",
    "vless-udp",
    "trojan-udp",
    "vmess-udp",
    "vmess-ws-udp",
    "vmess-http-udp",
]);

function getQuantumultXShape(n) {
    if (!n || !n.type) return "";

    switch (n.type) {
        case "ss": {
            if (n.plugin === "obfs" && (n.pluginMode || "").toLowerCase() === "http") {
                return "ss-http-udp";
            }
            return "ss-udp";
        }
        case "vless":
            return "vless-udp";
        case "trojan":
            return "trojan-udp";
        case "vmess": {
            const obfs = (n.obfs || "").toLowerCase();
            if (!obfs) return "vmess-udp";
            if (obfs === "ws") return "vmess-ws-udp";
            if (obfs === "http") return "vmess-http-udp";
            return "";
        }
        default:
            return "";
    }
}

// ========== Quantumult X 输出构建 ==========

function buildQuantumultXConfig(nodes) {
    const lines = [];

    for (const n of nodes) {
        const shape = getQuantumultXShape(n);
        if (!shape || !QX_ALLOWED_SHAPES.has(shape)) {
            continue;
        }

        if (n.type === "ss") {
            const { host, port } = normalizeHostPort(n.server, n.port);
            const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
            const method = n.cipher;
            const password = n.password;

            const parts = [];
            parts.push(`shadowsocks=${host}:${port}`);
            parts.push(`method=${method}`);
            parts.push(`password=${password}`);

            // HTTP / TLS 混淆
            if (n.plugin === "obfs" && n.pluginMode) {
                parts.push(`obfs=${n.pluginMode}`);
                if (n.pluginHost) {
                    parts.push(`obfs-host=${n.pluginHost}`);
                }
            }

            parts.push(`tag=${name}`);
            lines.push(parts.join(","));
        } else if (n.type === "vless") {
            const { host, port } = normalizeHostPort(n.server, n.port);
            const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
            const uuid = n.uuid || "";

            const parts = [];
            parts.push(`vless=${host}:${port}`);
            parts.push("method=none");
            if (uuid) {
                parts.push(`password=${uuid}`);
            }

            if (n.tls === "tls") {
                parts.push("over-tls=true");
            } else {
                parts.push("over-tls=false");
            }

            if (n.sni) {
                parts.push(`tls-host=${n.sni}`);
            }

            parts.push("udp-relay=true");
            parts.push(`tag=${name}`);

            lines.push(parts.join(","));
        } else if (n.type === "trojan") {
            const { host, port } = normalizeHostPort(n.server, n.port);
            const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
            const password = n.password || "";
            const overTls = true;
            const skipCert = !!n.skipCertVerify;

            const parts = [];
            parts.push(`trojan=${host}:${port}`);
            if (password) {
                parts.push(`password=${password}`);
            }
            parts.push(`over-tls=${overTls ? "true" : "false"}`);
            if (n.sni) {
                parts.push(`tls-host=${n.sni}`);
            }
            if (skipCert) {
                parts.push("tls-verification=false");
            } else {
                parts.push("tls-verification=true");
            }
            parts.push("udp-relay=true");
            parts.push(`tag=${name}`);

            lines.push(parts.join(","));
        } else if (n.type === "vmess") {
            const { host, port } = normalizeHostPort(n.server, n.port);
            const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
            const uuid = n.uuid || "";
            const method = "chacha20-ietf-poly1305";

            const parts = [];
            parts.push(`vmess=${host}:${port}`);
            parts.push(`method=${method}`);
            if (uuid) {
                parts.push(`password=${uuid}`);
            }

            if (n.obfs === "ws") {
                parts.push("obfs=ws");
                if (n.obfsUri) {
                    parts.push(`obfs-uri=${n.obfsUri}`);
                }
                if (n.obfsHost) {
                    parts.push(`obfs-host=${n.obfsHost}`);
                }
            } else if (n.obfs === "http") {
                parts.push("obfs=http");
                if (n.obfsUri) {
                    parts.push(`obfs-uri=${n.obfsUri}`);
                }
                if (n.obfsHost) {
                    parts.push(`obfs-host=${n.obfsHost}`);
                }
            }

            parts.push("aead=true");
            parts.push(`tag=${name}`);

            lines.push(parts.join(","));
        }
    }

    if (!lines.length) {
        return "# no shadowsocks/vless/trojan/vmess nodes\n";
    }
    return lines.join("\n") + "\n";
}

// host / port 正规化
function normalizeHostPort(server, port) {
    let host = server || "0.0.0.0";
    let p = port;
    if (!Number.isFinite(p)) {
        const m = /:(\d+)$/.exec(host);
        if (m) {
            p = parseInt(m[1], 10) || 0;
            host = host.slice(0, m.index);
        } else {
            p = 0;
        }
    }
    return { host, port: p || 0 };
}