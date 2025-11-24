export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 只处理 /api/paste 开头的路径
    if (!url.pathname.startsWith('/api/paste')) {
      return new Response('Not found', { status: 404 });
    }

    // 预检请求（OPTIONS）
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
        },
      });
    }

    // ===== GET /api/paste/:id 读取 =====
    if (request.method === 'GET') {
      const parts = url.pathname.split('/');
      const slug = parts[parts.length - 1] || '';
      if (!slug || slug === 'paste') {
        return json({ ok: false, error: 'Missing id' }, 400);
      }

      const raw = await env.Paste_KV.get(slug);
      if (!raw) {
        return json({ ok: false, error: 'Not found' }, 404);
      }

      const data = JSON.parse(raw);
      return json({ ok: true, ...data });
    }

    // ===== POST /api/paste  新建 / 更新 / 删除 =====
    if (request.method === 'POST') {
      const body = await request.json().catch(() => ({}));
      const { action, slug, filename, content, ttlKey, managePassword } = body;

      const ttlMap = {
        '10m': 10 * 60,
        '1d':  24 * 60 * 60,
        '7d':  7 * 24 * 60 * 60,
        '30d': 30 * 24 * 60 * 60,
        'forever': null,
      };
      const ttlSeconds = ttlMap[ttlKey] ?? ttlMap['10m'];

      const makeSlug = () =>
        Math.random().toString(36).slice(2, 10) +
        Math.random().toString(36).slice(2, 6);

      // === create 新建 ===
      if (action === 'create') {
        if (!content || !String(content).trim()) {
          return json({ ok: false, error: '内容不能为空' }, 400);
        }

        const newSlug = makeSlug();
        const now = Date.now();
        const hasPwd = !!(managePassword && managePassword.trim());

        const data = {
          slug: newSlug,
          filename: filename || '',
          content,
          ttlKey: ttlKey || '10m',
          hasPassword: hasPwd,
          passwordPlain: hasPwd ? managePassword : null, // 简版：明文保存
          createdAt: now,
          expiresAt: ttlSeconds ? now + ttlSeconds * 1000 : null,
        };

        const putOpts = ttlSeconds ? { expirationTtl: ttlSeconds } : {};
        await env.Paste_KV.put(newSlug, JSON.stringify(data), putOpts);

        return json({ ok: true, ...data });
      }

      // === update / delete 更新 / 删除 ===
      if (action === 'update' || action === 'delete') {
        if (!slug) {
          return json({ ok: false, error: '缺少 slug' }, 400);
        }

        const raw = await env.Paste_KV.get(slug);
        if (!raw) {
          return json({ ok: false, error: '内容不存在' }, 404);
        }

        const data = JSON.parse(raw);

        // 有密码就要校验
        if (data.hasPassword) {
          if (!managePassword) {
            return json({ ok: false, error: '需要管理密码' }, 401);
          }
          if (managePassword !== data.passwordPlain) {
            return json({ ok: false, error: '密码错误' }, 403);
          }
        }

        // 删除
        if (action === 'delete') {
          await env.Paste_KV.delete(slug);
          return json({ ok: true, deleted: true });
        }

        // 更新
        const now = Date.now();
        if (typeof filename === 'string') {
          data.filename = filename;
        }
        if (typeof content === 'string') {
          data.content = content;
        }
        data.ttlKey = ttlKey || data.ttlKey || '10m';
        data.expiresAt = ttlSeconds ? now + ttlSeconds * 1000 : null;

        const putOpts2 = ttlSeconds ? { expirationTtl: ttlSeconds } : {};
        await env.Paste_KV.put(slug, JSON.stringify(data), putOpts2);

        return json({ ok: true, ...data });
      }

      return json({ ok: false, error: '未知 action' }, 400);
    }

    // 其它方法 405
    return json({ ok: false, error: 'Method not allowed' }, 405);
  },
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
