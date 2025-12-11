/* shared/utils/hy2.js
 * 文件作用：
 *   - 解析 hysteria2:// / hy2:// 链接为结构化节点
 */

/* 解析 hysteria2://auth@server:port?xxx#tag */
export function parseHy2Url(urlStr) {
    try {
        const lower = urlStr.toLowerCase();
        let fixed = urlStr;
        if (lower.startsWith("hy2://")) {
            fixed = "hysteria2://" + urlStr.slice(6);
        }

        const url = new URL(fixed);
        const full = url.href;

        const withoutPrefix = full.slice("hysteria2://".length);
        const [userInfo, rest] = withoutPrefix.split("@");
        if (!userInfo || !rest) return null;

        const auth = decodeURIComponent(userInfo);

        const beforeHash = rest.split("#")[0];
        const [serverPort, queryStr] = beforeHash.split("?");
        const [server, portStr] = serverPort.split(":");
        const port = Number(portStr);
        if (!server || !port) return null;

        const name = decodeURIComponent((full.split("#")[1] || "").trim());
        const params = new URLSearchParams(queryStr || "");
        const sni = params.get("sni") || params.get("peer") || "";

        return {
            name,
            server,
            port,
            auth,
            sni,
        };
    } catch {
        return null;
    }
}