export function render(nodes) {
    // 先做 debug 风格输出，后续你再换成真实 proxies 输出
    let out = "proxies:\n";
    for (const n of nodes) {
        out += `  - name: "${n.name}"\n    type: "${n.type}"\n`;
    }
    return out.trimEnd();
}