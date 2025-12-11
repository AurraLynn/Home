export function renderQX(nodes = []) {
    const lines = [];
    lines.push("# Quantumult X passthrough (autosub)");
    for (const n of nodes) {
        if (!n?.raw) continue;
        lines.push(`# ${n.type}: ${n.raw}`);
    }
    return { body: lines.join("\n"), contentType: "text/plain; charset=utf-8" };
}