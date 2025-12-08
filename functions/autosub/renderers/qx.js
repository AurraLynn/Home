export function render(nodes) {
    return nodes.map((n) => `tag=${n.name}, type=${n.type}`).join("\n");
}1