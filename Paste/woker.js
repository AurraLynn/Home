export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;

        // CORS 预检
        if (request.method === "OPTIONS") {
            return new Response(null, {
                status: 204,
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type",
                    "Access-Control-Allow-Credentials": "true",
                },
            });
        }

        // 统一获取当前登录用户（用户名或 null）
        const currentUser = await getCurrentUser(request, env);

        // ========= 用户相关路由 =========

        // 注册：POST /api/auth/register
        if (path === "/api/auth/register" && request.method === "POST") {
            return handleRegister(request, env);
        }

        // 登录：POST /api/auth/login
        if (path === "/api/auth/login" && request.method === "POST") {
            return handleLogin(request, env);
        }

        // 退出登录：POST /api/auth/logout
        if (path === "/api/auth/logout" && request.method === "POST") {
            return handleLogout(request, env, currentUser);
        }

        // 用户中心：GET /api/me/pastes
        if (path === "/api/me/pastes" && request.method === "GET") {
            return handleMyPastes(request, env, currentUser);
        }

        // ========= Paste 接口 =========
        // 只处理 /api/paste 开头的，其它 /api/* 直接交给后端（比如 Card 的 functions/api）
        if (path.startsWith("/api/paste")) {
            if (request.method === "GET") {
                return handlePasteGet(request, env, currentUser);
            }

            if (request.method === "POST") {
                return handlePastePost(request, env, currentUser);
            }

            return json({ ok: false, error: "Method not allowed" }, 405);
        }

        // 走到这里说明是别的 /api/*（比如 /api/card/...）
        // 交给 origin（Pages / 其它服务），避免影响其他项目
        return fetch(request);
    },
};

/* ========== 通用工具 ========== */

function json(obj, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
            ...extraHeaders,
        },
    });
}

function text(body, status = 200) {
    return new Response(body, {
        status,
        headers: {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        },
    });
}

function parseCookies(header) {
    const out = {};
    if (!header) return out;
    const parts = header.split(";");
    for (const p of parts) {
        const [k, v] = p.split("=").map((s) => s.trim());
        if (!k) continue;
        out[k] = decodeURIComponent(v || "");
    }
    return out;
}

async function getCurrentUser(request, env) {
    const cookie = request.headers.get("Cookie") || "";
    const cookies = parseCookies(cookie);
    const sid = cookies["session"];
    if (!sid) return null;
    const raw = await env.USERS.get(`session:${sid}`);
    if (!raw) return null;
    try {
        const data = JSON.parse(raw);
        if (!data.username) return null;
        return data.username;
    } catch {
        return null;
    }
}

function makeRandomId(len = 32) {
    const chars =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "";
    for (let i = 0; i < len; i++) {
        out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
}

/* ========== 用户相关处理 ========== */

// 注册
async function handleRegister(request, env) {
    const body = await request.json().catch(() => ({}));
    const username = (body.username || "").toString().trim();
    const password = (body.password || "").toString();

    if (!username || !password) {
        return json({ ok: false, error: "用户名和密码不能为空" }, 400);
    }
    if (password.length < 6) {
        return json({ ok: false, error: "密码至少 6 位" }, 400);
    }

    const userKey = `user:${username}`;
    const exists = await env.USERS.get(userKey);
    if (exists) {
        return json({ ok: false, error: "用户名已存在" }, 409);
    }

    const userData = {
        username,
        // 简化处理：明文存储，个人项目够用；如果你介意，可以改成 hash
        password,
        createdAt: Date.now(),
    };
    await env.USERS.put(userKey, JSON.stringify(userData));

    return json({ ok: true });
}

// 登录（加入 remember）
async function handleLogin(request, env) {
    const body = await request.json().catch(() => ({}));
    const username = (body.username || "").toString().trim();
    const password = (body.password || "").toString();

    // ✅ 默认记住登录：remember 未传或不是 false，就当 true
    const remember = body.remember !== false;

    if (!username || !password) {
        return json({ ok: false, error: "用户名和密码不能为空" }, 400);
    }

    const userKey = `user:${username}`;
    const raw = await env.USERS.get(userKey);
    if (!raw) {
        return json({ ok: false, error: "用户名或密码错误" }, 401);
    }
    let user;
    try {
        user = JSON.parse(raw);
    } catch {
        return json({ ok: false, error: "用户数据损坏" }, 500);
    }
    if (user.password !== password) {
        return json({ ok: false, error: "用户名或密码错误" }, 401);
    }

    // 创建 session
    const sid = makeRandomId(32);
    const sessionData = {
        username,
        createdAt: Date.now(),
        remember, // 记录一下是否记住
    };

    // ✅ 记住登录：30 天；不记住：一天
    const ttlSeconds = remember ? 30 * 24 * 60 * 60 : 24 * 60 * 60;

    await env.USERS.put(`session:${sid}`, JSON.stringify(sessionData), {
        expirationTtl: ttlSeconds,
    });

    const cookieParts = [
        `session=${encodeURIComponent(sid)}`,
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
    ];
    // ✅ 记住登录时设置 Max-Age，这样浏览器重启也在
    if (remember) {
        cookieParts.push(`Max-Age=${ttlSeconds}`);
    }

    const cookie = cookieParts.join("; ");

    return json({ ok: true, username }, 200, { "Set-Cookie": cookie });
}

// 退出登录
async function handleLogout(request, env, currentUser) {
    const cookieHeader = request.headers.get("Cookie") || "";
    const cookies = parseCookies(cookieHeader);
    const sid = cookies["session"];
    if (sid) {
        await env.USERS.delete(`session:${sid}`);
    }
    const expiredCookie = [
        "session=;",
        "Path=/",
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Expires=Thu, 01 Jan 1970 00:00:00 GMT",
        "Max-Age=0",
    ].join("; ");

    return json({ ok: true }, 200, { "Set-Cookie": expiredCookie });
}

// 用户中心：列出当前用户的所有链接
async function handleMyPastes(request, env, currentUser) {
    if (!currentUser) {
        return json({ ok: false, error: "未登录" }, 401);
    }

    const idxKey = `index:${currentUser}`;
    const raw = await env.USERS.get(idxKey);
    let items = [];
    if (raw) {
        try {
            items = JSON.parse(raw);
            if (!Array.isArray(items)) items = [];
        } catch {
            items = [];
        }
    }

    return json({
        ok: true,
        items,
    });
}

/* ========== Paste 相关处理 ========== */

// GET /api/paste/:id
async function handlePasteGet(request, env, currentUser) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/");
    const slug = parts[parts.length - 1] || "";

    if (!slug || slug === "paste") {
        return json({ ok: false, error: "Missing id" }, 400);
    }

    const raw = await env.Paste.get(slug);
    if (!raw) {
        if (url.searchParams.get("manage") === "1") {
            return json({ ok: false, error: "Not found" }, 404);
        }
        return text("Not found", 404);
    }

    const data = JSON.parse(raw);

    // manage=1：管理模式专用（不再使用管理密码，只允许 owner）
    if (url.searchParams.get("manage") === "1") {
        // 如果有 owner，则必须登录且 owner 匹配
        if (data.owner && (!currentUser || currentUser !== data.owner)) {
            return json({ ok: false, error: "无权管理此内容" }, 403);
        }

        return json({
            ok: true,
            slug: data.slug,
            content: data.content,
            ttlKey: data.ttlKey || "10m",
            createdAt: data.createdAt || null,
            expiresAt: data.expiresAt || null,
            remark: data.remark || "",
            owner: data.owner || null,
        });
    }

    // 普通 GET：返回纯文本内容
    const body = (data.content || "").toString();
    return text(body, 200);
}

// POST /api/paste
async function handlePastePost(request, env, currentUser) {
    const url = new URL(request.url);
    const body = await request.json().catch(() => ({}));
    const { action, slug, content, ttlKey, remark, newSlug } = body;

    const ttlMap = {
        "10m": 10 * 60,
        "1d": 24 * 60 * 60,
        "7d": 7 * 24 * 60 * 60,
        "30d": 30 * 24 * 60 * 60,
        "forever": null, // 永不过期
    };

    // 注意：不能用 ??，不然 "forever" 的 null 会被替换成 10m
    let ttlSeconds;
    if (ttlKey && ttlKey in ttlMap) {
        ttlSeconds = ttlMap[ttlKey]; // 可能是 null（forever）
    } else {
        ttlSeconds = ttlMap["10m"]; // 默认 10 分钟
    }

    const makeRandomSlug = () =>
        Math.random().toString(36).slice(2, 2 + 4 + Math.floor(Math.random() * 6));

    // ---- 创建 ----
    if (action === "create") {
        const textContent = (content || "").toString().trim();
        if (!textContent) {
            return json({ ok: false, error: "内容不能为空" }, 400);
        }

        let finalSlug = (slug || "").toString().trim();
        if (!finalSlug) {
            finalSlug = makeRandomSlug();
        }

        // slug 限制：只允许 a-zA-Z0-9_-，否则报错
        if (!/^[A-Za-z0-9_-]+$/.test(finalSlug)) {
            return json(
                { ok: false, error: "自定义 URL 仅支持英文、数字、- 和 _。" },
                400
            );
        }

        const exists = await env.Paste.get(finalSlug);
        if (exists) {
            return json(
                { ok: false, error: "该 ID 已被占用，请换一个自定义 URL。" },
                409
            );
        }

        const now = Date.now();
        const owner = currentUser || null; // 未登录则为 null

        const data = {
            slug: finalSlug,
            content: textContent,
            ttlKey: ttlKey && ttlKey in ttlMap ? ttlKey : "10m",
            createdAt: now,
            expiresAt: ttlSeconds ? now + ttlSeconds * 1000 : null,
            owner,
            remark: (remark || "").toString().trim(),
        };

        const putOpts = ttlSeconds ? { expirationTtl: ttlSeconds } : {};
        await env.Paste.put(finalSlug, JSON.stringify(data), putOpts);

        // 登录用户：写入索引
        if (owner) {
            await appendUserIndex(env, owner, data);
        }

        return json({
            ok: true,
            slug: data.slug,
            content: data.content,
            ttlKey: data.ttlKey,
            createdAt: data.createdAt,
            expiresAt: data.expiresAt,
            owner: data.owner,
            remark: data.remark,
        });
    }

    // ---- 更新 / 删除 ----
    if (action === "update" || action === "delete") {
        const key = (slug || "").toString().trim();
        if (!key) {
            return json({ ok: false, error: "缺少 slug" }, 400);
        }

        const raw = await env.Paste.get(key);
        if (!raw) {
            return json({ ok: false, error: "内容不存在" }, 404);
        }

        const data = JSON.parse(raw);
        const owner = data.owner || null;

        // 权限控制：有 owner 的内容必须登录且 owner 匹配
        if (owner) {
            if (!currentUser) {
                return json({ ok: false, error: "未登录，无法管理此内容" }, 401);
            }
            if (currentUser !== owner) {
                return json({ ok: false, error: "无权管理此内容" }, 403);
            }
        } else {
            // 无 owner 的旧数据，可以选择：禁止管理
            return json(
                { ok: false, error: "此内容不支持管理（创建时未绑定用户）" },
                403
            );
        }

        // 删除
        if (action === "delete") {
            await env.Paste.delete(key);
            await removeFromUserIndex(env, owner, key);
            return json({ ok: true, deleted: true });
        }

        // 更新内容 / TTL / 备注 / 可选改 slug
        const now = Date.now();

        if (typeof content === "string") {
            data.content = content;
        }

        if (typeof remark === "string") {
            data.remark = remark.trim();
        }

        const newTtlKey = ttlKey || data.ttlKey || "10m";
        data.ttlKey = newTtlKey && newTtlKey in ttlMap ? newTtlKey : "10m";

        let newTtlSeconds;
        if (data.ttlKey && data.ttlKey in ttlMap) {
            newTtlSeconds = ttlMap[data.ttlKey]; // 允许为 null
        } else {
            newTtlSeconds = ttlMap["10m"];
        }

        data.expiresAt = newTtlSeconds ? now + newTtlSeconds * 1000 : null;

        const putOpts2 = newTtlSeconds ? { expirationTtl: newTtlSeconds } : {};

        let finalSlug = key;

        // 可选：改 slug（URL 重新自定义）
        if (newSlug && newSlug.toString().trim() && newSlug !== key) {
            const ns = newSlug.toString().trim();
            if (!/^[A-Za-z0-9_-]+$/.test(ns)) {
                return json(
                    {
                        ok: false,
                        error: "新的自定义 URL 仅支持英文、数字、- 和 _。",
                    },
                    400
                );
            }
            const existsNew = await env.Paste.get(ns);
            if (existsNew) {
                return json(
                    { ok: false, error: "新的 URL 已被占用，请换一个。" },
                    409
                );
            }
            // 删除旧 key，写入新 key
            await env.Paste.delete(key);
            data.slug = ns;
            await env.Paste.put(ns, JSON.stringify(data), putOpts2);
            finalSlug = ns;
            await renameInUserIndex(env, owner, key, ns, data);
        } else {
            // 不改 slug，直接覆盖
            await env.Paste.put(key, JSON.stringify(data), putOpts2);
            await updateUserIndex(env, owner, key, data);
        }

        return json({
            ok: true,
            slug: finalSlug,
            content: data.content,
            ttlKey: data.ttlKey,
            createdAt: data.createdAt,
            expiresAt: data.expiresAt,
            owner: data.owner || owner,
            remark: data.remark || "",
        });
    }

    return json({ ok: false, error: "未知 action" }, 400);
}

/* ========== 用户索引辅助函数 ========== */

async function loadUserIndex(env, username) {
    const idxKey = `index:${username}`;
    const raw = await env.USERS.get(idxKey);
    if (!raw) return [];
    try {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) return arr;
        return [];
    } catch {
        return [];
    }
}

async function saveUserIndex(env, username, items) {
    const idxKey = `index:${username}`;
    await env.USERS.put(idxKey, JSON.stringify(items));
}

async function appendUserIndex(env, username, pasteData) {
    const items = await loadUserIndex(env, username);
    const entry = {
        slug: pasteData.slug,
        remark: pasteData.remark || "",
        createdAt: pasteData.createdAt || Date.now(),
        expiresAt: pasteData.expiresAt || null,
    };
    items.unshift(entry); // 最新在前
    await saveUserIndex(env, username, items);
}

async function removeFromUserIndex(env, username, slug) {
    const items = await loadUserIndex(env, username);
    const filtered = items.filter((it) => it.slug !== slug);
    await saveUserIndex(env, username, filtered);
}

async function updateUserIndex(env, username, slug, pasteData) {
    const items = await loadUserIndex(env, username);
    const updated = items.map((it) => {
        if (it.slug !== slug) return it;
        return {
            slug,
            remark: pasteData.remark || "",
            createdAt: pasteData.createdAt || it.createdAt || Date.now(),
            expiresAt: pasteData.expiresAt || null,
        };
    });
    await saveUserIndex(env, username, updated);
}

async function renameInUserIndex(env, username, oldSlug, newSlug, pasteData) {
    const items = await loadUserIndex(env, username);
    const updated = items.map((it) => {
        if (it.slug !== oldSlug) return it;
        return {
            slug: newSlug,
            remark: pasteData.remark || "",
            createdAt: pasteData.createdAt || it.createdAt || Date.now(),
            expiresAt: pasteData.expiresAt || null,
        };
    });
    await saveUserIndex(env, username, updated);
}