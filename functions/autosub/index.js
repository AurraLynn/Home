import { renderSubscription } from "./Exit.js";

function getPasteKV(env) {
    return env?.Paste_Sub || null;
}

async function loadFromKVById(env, id) {
    if (!id) return "";

    const kv = getPasteKV(env);
    if (!kv) throw new Error("KV namespace `Paste_Sub` not bound");

    const rec = await kv.get(id, "json").catch(() => null);
    if (rec && typeof rec === "object") {
        const raw = rec.content || rec.text || rec.data || rec.raw || rec.value || "";
        return raw && String(raw).trim() ? String(raw) : "";
    }

    const stored = await kv.get(id);
    if (!stored) return "";
    const s = String(stored).trim();
    if (!s) return "";

    try {
        const obj = JSON.parse(s);
        const raw = obj?.content || obj?.text || obj?.data || obj?.raw || obj?.value || "";
        if (raw && String(raw).trim()) return String(raw);
    } catch {}

    return s;
}

async function loadRawPack(request, env) {
    const url = new URL(request.url);

    const qText = url.searchParams.get("text");
    if (qText && qText.trim()) return { rawText: qText, source: "query:text" };

    if (request.method === "POST") {
        const body = await request.text();
        if (body && body.trim()) return { rawText: body, source: "post:body" };
    }

    const id = (url.searchParams.get("id") || "").trim();
    if (id) {
        const t = await loadFromKVById(env, id);
        return { rawText: t || "", source: t ? "kv:record.content" : "kv:miss" };
    }

    return { rawText: "", source: "none" };
}

function detectClient(request) {
    const url = new URL(request.url);

    const q = (url.searchParams.get("client") || "").trim().toLowerCase();
    if (q) return q;

    const ua = (request.headers.get("user-agent") || "").toLowerCase();
    if (ua.includes("stash")) return "stash";
    if (ua.includes("surge")) return "surge";
    if (ua.includes("quantumult")) return "qx";
    if (ua.includes("loon")) return "loon";
    if (ua.includes("shadowrocket")) return "shadowrocket";
    if (ua.includes("clash") || ua.includes("mihomo") || ua.includes("meta")) return "clash";
    if (ua.includes("sing-box") || ua.includes("singbox")) return "singbox";

    return "v2ray";
}

function buildHelp(client, source) {
    return [
        "AUTOSUB: no source content",
        "",
        "Usage:",
        "  1) GET  /autosub?text=RAW_TEXT",
        "  2) POST /autosub  (body = RAW_TEXT)",
        "  3) GET  /autosub?id=PASTE_ID  (KV: Paste_Sub -> record.content)",
        "",
        "Client:",
        "  /autosub?client=clash|surge|qx|v2ray",
        "",
        `Current client = ${client}`,
        `Source = ${source}`,
    ].join("\n");
}

export async function onRequest(context) {
    const { request, env } = context;
    const url = new URL(request.url);

    const debug = url.searchParams.get("debug") === "1";
    const client = detectClient(request);

    let rawPack;
    try {
        rawPack = await loadRawPack(request, env);
    } catch (e) {
        if (debug) {
            return new Response(JSON.stringify({
                ok: false,
                error: String(e?.message || e),
                hasPasteSubBinding: !!env?.Paste_Sub,
                client,
            }, null, 2), {
                status: 500,
                headers: { "content-type": "application/json; charset=utf-8" },
            });
        }
        return new Response(String(e?.message || e), { status: 500 });
    }

    const { rawText, source } = rawPack;

    if (debug) {
        return new Response(JSON.stringify({
            ok: true,
            debug: true,
            route: "/autosub",
            id: url.searchParams.get("id") || null,
            client,
            source,
            hasPasteSubBinding: !!env?.Paste_Sub,
            rawLength: rawText ? String(rawText).length : 0,
        }, null, 2), {
            headers: {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-store",
            },
        });
    }

    if (!rawText || !rawText.trim()) {
        return new Response(buildHelp(client, source), {
            status: 400,
            headers: { "content-type": "text/plain; charset=utf-8" },
        });
    }

    const { body, contentType } = renderSubscription(rawText, {
        client,
        source,
        query: Object.fromEntries(url.searchParams.entries()),
    });

    return new Response(body || "", {
        headers: {
            "content-type": contentType || "text/plain; charset=utf-8",
            "cache-control": "no-store",
        },
    });
}