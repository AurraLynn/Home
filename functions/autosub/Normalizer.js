export function normalizeNodes(nodes = []) {
    const seen = new Set();
    const out = [];

    for (const n of nodes) {
        if (!n || !n.raw) continue;
        const key = `${n.type}:${n.raw}`;
        if (seen.has(key)) continue;
        seen.add(key);

        out.push({
            ...n,
            name: n.name || "",
        });
    }

    return out;
}