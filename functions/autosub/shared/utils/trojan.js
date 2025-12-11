/* shared/utils/trojan.js
 * 文件作用：
 *   - 解析 trojan:// 链接为结构化节点
 */

/* 解析 trojan://password@server:port?xxx#tag */
export function parseTrojanUrl(urlStr) {
    try {
        const url = new URL(urlStr);
        const full = url.href;

        const withoutPrefix = full.slice(9); // 去掉 trojan://
        const [userInfo, rest] = withoutPrefix.split("@");
        if (!userInfo || !rest) return null;

        const password = userInfo;

        const beforeHash = rest.split("#")[0];
        const [serverPort, queryStr] = beforeHash.split("?");
        const [server, portStr] = serverPort.split(":");
        const port = Number(portStr);
        if (!server || !port) return null;

        const name = decodeURIComponent((full.split("#")[1] || "").trim());

        const params = new URLSearchParams(queryStr || "");
        const sni =
            params.get("sni") ||
            params.get("peer") ||
            params.get("host") ||
            "";

        const allowInsecure = params.get("allowInsecure") === "1";

        return {
            name,
            server,
            port,
            password,
            sni,
            allowInsecure,
        };
    } catch {
        return null;
    }
}