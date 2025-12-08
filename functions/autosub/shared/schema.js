export const NODE_SCHEMA = {
    base: ["type", "name", "server", "port", "udp"],
    auth: ["uuid", "password", "method", "auth", "psk", "username"],
    security: ["security", "tls", "sni", "alpn", "fp", "insecure", "flow", "pbk", "sid"],
    transport: ["network", "host", "path", "headers", "serviceName", "authority"],
    misc: ["plugin", "pluginOpts", "obfs", "ports"],
    extra: ["extra"],
};