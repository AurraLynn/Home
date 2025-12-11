/* shared/utils/ss.js
 * 文件作用：
 *   - 解析 ss:// 链接为结构化节点
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

/* 解析 ss://url → { server, port, cipher, password, name } */
export function parseSSUrl(url) {
    try {
        const withoutPrefix = url.slice(5); // 去掉 ss://
        let main = withoutPrefix;
        let tag = "";

        const hashIndex = withoutPrefix.indexOf("#");
        if (hashIndex !== -1) {
            main = withoutPrefix.slice(0, hashIndex);
            tag = decodeURIComponent(withoutPrefix.slice(hashIndex + 1));
        }

        let plugin = "";
        const qIndex = main.indexOf("?");
        if (qIndex !== -1) {
            plugin = main.slice(qIndex + 1);
            main = main.slice(0, qIndex);
        }

        // 如果 main 里没有 '@'，认为是 base64(method:password@server:port)
        if (!main.includes("@")) {
            const decoded = decodeBase64(main);
            if (decoded && decoded.includes("@")) {
                main = decoded;
            }
        }

        const [userInfo, serverPart] = main.split("@");
        if (!userInfo || !serverPart) return null;

        const [method, password] = userInfo.split(":");
        const [server, portStr] = serverPart.split(":");

        const port = Number(portStr);
        if (!server || !port) return null;

        return {
            server,
            port,
            cipher: method,
            password,
            plugin,
            name: tag,
        };
    } catch {
        return null;
    }
}