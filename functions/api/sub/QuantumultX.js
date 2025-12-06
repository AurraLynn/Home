// functions/api/sub/QuantumultX.js
//
// 支持类型输入：
// -  URL格式
// -  URL/Base64 混合格式
// -  Base64（单条、多条、整条订阅）
//
// 支持协议输出：
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
// -  只处理 Quantumult X，供 /api/sub/Converter 内部调用
//
// 客户端：
// -  Quantumult X仅支持现有输出协议

export async function onRequestPost(context) {
    const { request } = context;
    const rawText = await request.text();
    const text = rawText || "";

    // 按行拆分，去掉空行和注释
    const linesRaw = text
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("//"));

    if (!linesRaw.length) {
        return new Response("# empty\n", {
            status: 200,
            headers: { "content-type": "text/plain; charset=utf-8" },
        });
    }

    // 单行时尝试当成 Base64 订阅整体解码
    let lines = linesRaw;
    if (linesRaw.length === 1) {
        const decodedAll = safeBase64Decode(linesRaw[0]);
        if (
            decodedAll &&
            decodedAll !== linesRaw[0] &&
            (decodedAll.includes("://") || decodedAll.includes("\n"))
        ) {
            lines = decodedAll
                .split(/\r?\n/)
                .map((l) => l.trim())
                .filter((l) => l && !l.startsWith("//"));
        }
    }

    const nodes = [];

    for (const lineRaw of lines) {
        const line = lineRaw.trim();
        if (!line) continue;

        const lower = line.toLowerCase();

        if (lower.startsWith("ss://")) {
            nodes.push(parseShadowsocksLenient(line));
            continue;
        }

        if (lower.startsWith("vless://")) {
            nodes.push(parseVlessLenient(line));
            continue;
        }

        if (lower.startsWith("trojan://")) {
            nodes.push(parseTrojanLenient(line));
            continue;
        }

        if (lower.startsWith("vmess://")) {
            nodes.push(parseVmessLenient(line));
            continue;
        }

        // 尝试当成 Base64 单条节点解码
        const decoded = safeBase64Decode(line);
        if (decoded && decoded !== line) {
            const d = decoded.trim();
            const dl = d.toLowerCase();

            if (dl.startsWith("ss://")) {
                nodes.push(parseShadowsocksLenient(d));
                continue;
            }
            if (dl.startsWith("vless://")) {
                nodes.push(parseVlessLenient(d));
                continue;
            }
            if (dl.startsWith("trojan://")) {
                nodes.push(parseTrojanLenient(d));
                continue;
            }
            if (dl.startsWith("vmess://")) {
                nodes.push(parseVmessLenient(d));
                continue;
            }
        }

        // 未识别的行丢弃
    }

    const outText = buildQuantumultXConfig(nodes);

    return new Response(outText, {
        status: 200,
        headers: { "content-type": "text/plain; charset=utf-8" },
    });
}

/* ========== Base64 工具 ========== */

function safeBase64Decode(input) {
    try {
        let s = (input || "").trim();
        if (!s) return "";

        s = s.replace(/-/g, "+").replace(/_/g, "/");
        const pad = (-s.length) % 4;
        if (pad > 0) s += "=".repeat(pad);

        return decodeURIComponent(escape(atob(s)));
    } catch (_e) {
        return "";
    }
}

/* ========== Shadowsocks 解析：ss:// ========== */

function parseShadowsocksLenient(uri) {
    try {
        let u = uri.replace(/^ss:\/\//i, "");

        // 备注（节点名）
        let name = "";
        const hashIndex = u.indexOf("#");
        if (hashIndex !== -1) {
            const remarkPart = u.slice(hashIndex + 1);
            try {
                name = decodeURIComponent(remarkPart);
            } catch (_e) {
                name = remarkPart;
            }
            u = u.slice(0, hashIndex);
        }

        let userinfoPart = "";
        let serverPart = "";

        const atIndex = u.lastIndexOf("@");
        if (atIndex !== -1) {
            userinfoPart = u.slice(0, atIndex);
            serverPart = u.slice(atIndex + 1);
        } else {
            // 可能是 ss://Base64(method:pwd@host:port)
            const decoded = safeBase64Decode(u);
            if (decoded && decoded.includes("@")) {
                const idx = decoded.indexOf("@");
                userinfoPart = decoded.slice(0, idx);
                serverPart = decoded.slice(idx + 1);
            } else {
                serverPart = u;
            }
        }

        // userinfo 可能是 Base64(method:pwd)
        let userinfo = userinfoPart;
        if (userinfo && !userinfo.includes(":")) {
            const decodedUser = safeBase64Decode(userinfo);
            if (decodedUser && decodedUser.includes(":")) {
                userinfo = decodedUser;
            }
        }

        let cipher = "aes-128-gcm";
        let password = "";

        if (userinfo && userinfo.includes(":")) {
            const idx = userinfo.indexOf(":");
            cipher = userinfo.slice(0, idx);
            password = userinfo.slice(idx + 1);
        }

        // serverPart 可能带 query
        let hostPortRaw = serverPart;
        let queryStr = "";
        const qIndex = serverPart.indexOf("?");
        if (qIndex !== -1) {
            hostPortRaw = serverPart.slice(0, qIndex);
            queryStr = serverPart.slice(qIndex + 1);
        }
        hostPortRaw = (hostPortRaw || "").trim();

        // 提取 host + port，避免出现 "host:port/xxx" 导致 NaN
        let server = hostPortRaw || "0.0.0.0";
        let port = 8388;
        const m = /^(.*):(\d+)$/.exec(hostPortRaw);
        if (m) {
            server = m[1];
            port = parseInt(m[2], 10) || 8388;
        }

        let plugin = "";
        let pluginMode = "";
        let pluginHost = "";

        if (queryStr) {
            const q = new URLSearchParams(queryStr);
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

        return {
            raw: uri,
            scheme: "ss",
            type: "ss",

            name: name || `${server}:${port}`,
            server,
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
            server: "0.0.0.0",
            port: 8388,
            cipher: "aes-128-gcm",
            password: "",
            plugin: "",
            pluginMode: "",
            pluginHost: "",
        };
    }
}

/* ========== VLESS 解析：vless:// （仅 UDP） ========== */

function parseVlessLenient(uri) {
    try {
        let u = uri.replace(/^vless:\/\//i, "");

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

        const atIndex = userinfoHostPort.indexOf("@");
        if (atIndex === -1) throw new Error("invalid vless");

        const userinfo = userinfoHostPort.slice(0, atIndex);
        const hostPortRaw = userinfoHostPort.slice(atIndex + 1);

        const parts = userinfo.split(":");
        const uuid = parts[parts.length - 1] || "";

        const hostPort = hostPortRaw.trim();
        let host = hostPort || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPort);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            host = hostPort.slice(0, m.index);
        }

        let name = `${host}:${port}`;
        let tls = "";
        let sni = "";
        let path = "";
        let pbk = "";

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

            path = q.get("path") || q.get("obfs-uri") || "";
            pbk = q.get("pbk") || "";
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
            pbk,
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
            pbk: "",
        };
    }
}

/* ========== VMESS 解析：vmess://（UDP / WS / HTTP） ========== */

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

        const atIndex = userinfoHostPort.indexOf("@");
        if (atIndex === -1) throw new Error("invalid vmess");

        const userinfo = userinfoHostPort.slice(0, atIndex);
        const hostPortRaw = userinfoHostPort.slice(atIndex + 1);

        const parts = userinfo.split(":");
        const uuid = parts[parts.length - 1] || "";

        const hostPort = hostPortRaw.trim();
        let host = hostPort || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPort);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            host = hostPort.slice(0, m.index);
        }

        let name = `${host}:${port}`;
        let obfs = "";
        let obfsHost = "";
        let obfsUri = "";
        let tls = "";

        if (queryStr) {
            const q = new URLSearchParams(queryStr);

            const r =
                q.get("remarks") ||
                q.get("name") ||
                q.get("tag") ||
                q.get("remark") ||
                q.get("ps");
            if (r) {
                try {
                    name = decodeURIComponent(r);
                } catch (_e) {
                    name = r;
                }
            }

            const obfsType = (q.get("obfs") || "").toLowerCase();
            const hostFrom = q.get("obfsParam") || q.get("host") || q.get("sni") || "";
            const path = q.get("path") || q.get("obfs-uri") || "/";

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
            obfsUri: "",
            tls: "",
        };
    }
}

/* ========== Trojan 解析：trojan://（UDP） ========== */

function parseTrojanLenient(uri) {
    try {
        let u = uri.replace(/^trojan:\/\//i, "");

        let name = "";
        const hashIndex = u.indexOf("#");
        if (hashIndex !== -1) {
            const remarkPart = u.slice(hashIndex + 1);
            try {
                name = decodeURIComponent(remarkPart);
            } catch (_e) {
                name = remarkPart;
            }
            u = u.slice(0, hashIndex);
        }

        let main = u;
        let queryStr = "";
        const qIndex = u.indexOf("?");
        if (qIndex !== -1) {
            main = u.slice(0, qIndex);
            queryStr = u.slice(qIndex + 1);
        }

        const atIndex = main.lastIndexOf("@");
        let password = "";
        let hostPortRaw = "";
        if (atIndex !== -1) {
            password = main.slice(0, atIndex);
            hostPortRaw = main.slice(atIndex + 1);
        } else {
            hostPortRaw = main;
        }

        try {
            password = decodeURIComponent(password);
        } catch (_e) {}

        hostPortRaw = (hostPortRaw || "").trim();
        let server = hostPortRaw || "0.0.0.0";
        let port = 443;
        const m = /:(\d+)$/.exec(hostPortRaw);
        if (m) {
            port = parseInt(m[1], 10) || 443;
            server = hostPortRaw.slice(0, m.index);
        }

        let allowInsecure = "";
        let peer = "";
        if (queryStr) {
            const q = new URLSearchParams(queryStr);
            allowInsecure =
                q.get("allowInsecure") || q.get("allow_insecure") || "";
            peer = q.get("peer") || q.get("sni") || "";
        }

        const overTls = true;
        const tlsVerification = !(
            allowInsecure === "1" ||
            allowInsecure === "true" ||
            allowInsecure === "yes"
        );
        const tlsHost = peer || server;

        if (!name) {
            name = `${tlsHost}:${port}`;
        }

        return {
            raw: uri,
            scheme: "trojan",
            type: "trojan",

            name,
            server,
            port,
            password,

            overTls,
            tlsVerification,
            tlsHost,
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
            overTls: true,
            tlsVerification: true,
            tlsHost: "",
        };
    }
}

/* ========== host:port 规范化 ========== */

function normalizeHostPort(server, port) {
    let host = (server || "").trim();
    let finalPort = port;

    // 去掉 path / query
    const cut = host.search(/[\/\?]/);
    if (cut !== -1) {
        host = host.slice(0, cut);
    }

    const m = /^(.*):(\d+)$/.exec(host);
    if (m) {
        host = m[1];
        finalPort = parseInt(m[2], 10) || finalPort;
    }

    if (!Number.isFinite(finalPort) || finalPort <= 0) {
        finalPort = 443;
    }

    return { host, port: finalPort };
}

/* ========== 输出：Quantumult X 配置 ========== */

function buildQuantumultXConfig(nodes) {
    const lines = [];

    for (const n of nodes) {
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
            parts.push(`tag=${name}`);

            lines.push(parts.join(","));
        } else if (n.type === "trojan") {
            const { host, port } = normalizeHostPort(n.server, n.port);
            const name = (n.name || `${host}:${port}`).replace(/,/g, " ");
            const password = n.password || "";
            const overTls = n.overTls ? "true" : "false";
            const tlsVerification = n.tlsVerification ? "true" : "false";
            const tlsHost = n.tlsHost || host;

            const parts = [];
            parts.push(`trojan=${host}:${port}`);
            parts.push(`password=${password}`);
            parts.push(`over-tls=${overTls}`);
            parts.push(`tls-verification=${tlsVerification}`);
            if (tlsHost) {
                parts.push(`tls-host=${tlsHost}`);
            }
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