function b64DecodeUrlSafe(input) {
    if (!input) return "";
    let s = String(input).replace(/-/g, "+").replace(/_/g, "/");
    const pad = s.length % 4;
    if (pad) s += "=".repeat(4 - pad);
    try {
        return decodeURIComponent(escape(atob(s)));
    } catch {
        try { return atob(s); } catch { return ""; }
    }
}

function parseSSRaw(raw) {
    const s = String(raw || "").trim();
    if (!s.startsWith("ss://")) return null;

    let rest = s.slice(5);

    let name = "";
    const hashIndex = rest.indexOf("#");
    if (hashIndex >= 0) {
        name = decodeURIComponent(rest.slice(hashIndex + 1));
        rest = rest.slice(0, hashIndex);
    }

    const qIndex = rest.indexOf("?");
    if (qIndex >= 0) rest = rest.slice(0, qIndex);

    // BASE64(method:pass)@host:port
    if (rest.includes("@")) {
        const [b64Part, hostPart] = rest.split("@");
        const decoded = b64DecodeUrlSafe(b64Part);
        const [cipher, password] = decoded.split(":");
        const [server, portStr] = hostPart.split(":");
        const port = Number(portStr);
        if (!cipher || !password || !server || !port) return null;
        return { type: "ss", server, port, cipher, password, name: name || `${server}:${port}` };
    }

    // BASE64(method:pass@host:port)
    const decoded = b64DecodeUrlSafe(rest);
    if (decoded.includes("@")) {
        const [left, right] = decoded.split("@");
        const [cipher, password] = left.split(":");
        const [server, portStr] = right.split(":");
        const port = Number(portStr);
        if (!cipher || !password || !server || !port) return null;
        return { type: "ss", server, port, cipher, password, name: name || `${server}:${port}` };
    }

    return null;
}

function nodeToClashProxy(node) {
    if (!node) return null;

    if (node.type === "ss" && node.raw) {
        const p = parseSSRaw(node.raw);
        if (!p) return null;
        return {
            type: "ss",
            server: p.server,
            port: p.port,
            cipher: p.cipher,
            password: p.password,
            name: p.name,
        };
    }

    return null;
}

export function renderClash(nodes = []) {
    const proxies = [];

    for (const n of nodes) {
        if (n?.type !== "ss") continue;
        const p = nodeToClashProxy(n);
        if (p) proxies.push(p);
    }

    const names = proxies.map(p => p.name);

    const lines = [];
    lines.push(`port: 7890`);
    lines.push(`socks-port: 7891`);
    lines.push(`mode: Rule`);
    lines.push(`allow-lan: true`);
    lines.push(`log-level: info`);
    lines.push(``);
    lines.push(`dns:`);
    lines.push(`  enable: true`);
    lines.push(`  listen: 0.0.0.0:53`);
    lines.push(`  ipv6: false`);
    lines.push(`  nameserver:`);
    lines.push(`    - 223.5.5.5`);
    lines.push(`    - 223.6.6.6`);
    lines.push(``);
    lines.push(`proxies:`);

    if (proxies.length === 0) {
        lines.push(`  # no supported proxies parsed yet`);
    } else {
        for (const p of proxies) {
            lines.push(`  - ${JSON.stringify(p)}`);
        }
    }

    lines.push(``);
    lines.push(`proxy-groups:`);
    lines.push(`  - name: "🐹Lyn · Node"`);
    lines.push(`    type: select`);
    lines.push(`    proxies:`);

    if (names.length === 0) {
        lines.push(`      - DIRECT`);
    } else {
        for (const name of names) {
            lines.push(`      - "${name}"`);
        }
    }

    lines.push(``);
    lines.push(`rules:`);
    lines.push(`  - GEOIP,LAN,DIRECT`);
    lines.push(`  - GEOIP,CN,DIRECT`);
    lines.push(`  - MATCH,🐹Lyn · Node`);

    return {
        body: lines.join("\n"),
        contentType: "text/yaml; charset=utf-8",
    };
}