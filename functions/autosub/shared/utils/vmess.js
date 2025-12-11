/* shared/utils/vmess.js
 * 文件作用：
 *   - 解析 vmess:// 链接（Base64 JSON）为结构化节点
 */

function decodeBase64(str) {
    try {
        return decodeURIComponent(escape(atob(str)));
    } catch {
        try {
            return atob(str);
        } catch {
            return "";
        }
    }
}

/* 解析 vmess://... → { server, port, id, aid, net, path, host, sni, ... } */
export function parseVmessUrlOrJson(url) {
    try {
        const raw = url.slice(8); // 去掉 vmess://
        const decoded = decodeBase64(raw);
        if (!decoded) return null;

        const obj = JSON.parse(decoded);
        const port = Number(obj.port);

        return {
            name: obj.ps || "",
            server: obj.add,
            port,
            id: obj.id,
            uuid: obj.id,
            alterId: obj.aid ? Number(obj.aid) : 0,
            security: obj.scy || obj.security || "auto",
            network: obj.net || "tcp",
            host: obj.host || "",
            path: obj.path || "/",
            sni: obj.sni || obj.tlsServerName || "",
            tls: obj.tls === "tls",
        };
    } catch {
        return null;
    }
}