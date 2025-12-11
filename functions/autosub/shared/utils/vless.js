/* shared/utils/vless.js
 * 文件作用：
 *   - 解析 vless:// 链接为结构化节点
 */

/* 解析 vless://uuid@server:port?xxx#tag */
export function parseVlessUrl(urlStr) {
    try {
        const url = new URL(urlStr);
        const full = url.href; // 保留原始
        const protocol = url.protocol.toLowerCase();
        if (protocol !== "vless:") return null;

        const [uuid, hostPort] = full.slice(8).split("@");
        if (!uuid || !hostPort) return null;

        const hp = hostPort.split("#")[0].split("?")[0];
        const [server, portStr] = hp.split(":");
        const port = Number(portStr);
        if (!server || !port) return null;

        const params = url.searchParams;
        const name = decodeURIComponent((full.split("#")[1] || "").trim());

        const security = params.get("security") || "";
        const sni = params.get("sni") || params.get("peer") || "";
        const flow = params.get("flow") || "";
        const type = params.get("type") || params.get("network") || "tcp";
        const host = params.get("host") || "";
        const path = params.get("path") || "/";

        return {
            name,
            server,
            port,
            id: uuid,
            uuid,
            security,
            flow,
            network: type,
            host,
            path,
            sni,
        };
    } catch {
        return null;
    }
}