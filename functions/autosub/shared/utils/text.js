export function splitMixedTextToLines(text) {
    const s = String(text || "");
    const rows = s.replace(/\r/g, "\n").split("\n");

    const out = [];

    for (const row of rows) {
        const r = row.trim();
        if (!r) continue;

        const parts = r.split(/\s+|,|;|\|/g).filter(Boolean);
        for (const p of parts) {
            const v = String(p).trim();
            if (v) out.push(v);
        }
    }

    return out;
}