1export function render(nodes) {
    return nodes.map((n) => `${n.name} = ${n.type}`).join("\n");
}