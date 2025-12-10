/**
 * autosub/Router.js
 *
 * 作用：
 *   - 根据 client 类型选择对应渲染器（Clash / Surge / v2ray 兜底）
 *   - 提供 UA → client 的简单判断函数（备用）
 *   - v2ray 兜底输出时，避免“已经是订阅 Base64 又被二次 Base64”这种情况
 */

import { renderClash } from "./renderers/clash.js";
import { renderSurge } from "./renderers/surge.js";

/**
 * （备用）根据 UA 判断客户端类型
 * 当前 index.js 已经内置了一份逻辑，这里保留一份以防后续 exit/其它地方用到
 */
export function pickClientFromUA(uaRaw) {
  const ua = (uaRaw || "").toLowerCase();

  if (!ua) return "v2ray";

  if (ua.includes("surge")) {
    return "surge";
  }

  if (
    ua.includes("clash") ||
    ua.includes("mihomo") ||
    ua.includes("meta") ||
    ua.includes("cfw") ||
    ua.includes("clash for windows")
  ) {
    return "clash";
  }

  return "v2ray";
}

/**
 * 安全转换为 Base64（兼容中文）
 *
 * 注意：
 *   - 只在「原始文本不是订阅 Base64」时使用
 *   - 如果原始文本本身就是 Base64 订阅，就不要再包一层
 */
function toB64(text) {
  const t = String(text || "").trim();
  if (!t) return "";
  return btoa(unescape(encodeURIComponent(t)));
}

/**
 * 简单判断一段字符串里是否有“节点协议前缀”
 * 用于：
 *   1. 判断原始内容是否已经是节点列表
 *   2. 判断 Base64 解码后的内容是不是订阅
 */
function containsNodeProtocol(str) {
  if (!str) return false;
  const t = String(str).toLowerCase();

  return (
    t.includes("ss://") ||
    t.includes("vmess://") ||
    t.includes("vless://") ||
    t.includes("trojan://") ||
    t.includes("hysteria2://") ||
    t.includes("hy2://") ||
    t.includes("hysteria://")
  );
}

/**
 * 安全地尝试做一次 Base64 解码
 * 用于检测：
 *   - 某串“看起来像 Base64”的东西，解出来是不是节点列表
 * 不会抛异常，只返回空串表示失败
 */
function safeAtobDetect(b64) {
  if (!b64) return "";
  const s = String(b64).trim();

  try {
    // 先尝试 UTF-8 友好的方式
    return decodeURIComponent(escape(atob(s)));
  } catch (e) {
    try {
      // 不行再退回原始 atob
      return atob(s);
    } catch {
      return "";
    }
  }
}

/**
 * 粗略判断原始文本是不是“订阅 Base64 串”
 *
 * 判定规则：
 *   1. 自身不包含 ss:// / vmess:// 等协议前缀（否则就是明文节点列表）
 *   2. 只包含 Base64 允许的字符
 *   3. 解码后出现任意协议前缀 → 认为是订阅 Base64
 */
function looksLikeBase64Subscription(raw) {
  const text = String(raw || "").trim();
  if (!text) return false;

  // 1）自身已经包含协议前缀，说明是节点列表，不是订阅 Base64
  if (containsNodeProtocol(text)) return false;

  // 2）简单校验字符集是否像 Base64
  const compact = text.replace(/\s+/g, "");
  const base64ish = /^[A-Za-z0-9+/=]+$/.test(compact);
  if (!base64ish) return false;

  // 3）尝试解码，如果解出来包含协议，则认定为订阅 Base64
  const decoded = safeAtobDetect(compact);
  if (!decoded) return false;

  return containsNodeProtocol(decoded);
}

/**
 * 总路由函数：
 *   - 输入：解析后的节点数组 + 环境信息（client / rawText / query / source / ua）
 *   - 输出：{ body, contentType }
 *
 * 逻辑：
 *   - client=clash → 调用 renderClash 输出完整 YAML 配置
 *   - client=surge → 调用 renderSurge 输出 [Proxy] 段
 *   - 其它（包括 v2ray ）→ 输出 Base64 订阅（带“二次 Base64 防呆”）
 */
export function routeAndRender(
  nodes,
  {
    client = "v2ray",
    rawText = "",
    query = {},
    source = "",
    ua = "",
  } = {},
) {
  const c = String(client || "v2ray").toLowerCase();

  // ==== Clash：输出简易完整配置（含代理组、规则模板） ====
  if (c === "clash") {
    return renderClash(nodes, {
      client,
      query,
      source,
      rawText,
      ua,
    });
  }

  // ==== Surge：只输出 [Proxy] 段（你现在的需求是只要节点，不管规则） ====
  if (c === "surge") {
    return renderSurge(nodes, {
      client,
      query,
      source,
      rawText,
      ua,
    });
  }

  // ==== v2ray／兜底：输出 Base64 订阅 ====
  //
  // 核心是防止这种情况：
  //   - 用户传进来的是一整串“已经是订阅 Base64”的字符串
  //   - 我们又对它调用了一次 toB64，结果客户端解析失败
  //
  // 策略：
  //   - 如果 looksLikeBase64Subscription(original) === true：
  //         → 认为用户已经给的是订阅 Base64，原样返回
  //   - 否则：
  //         → 把 original 当“明文节点列表”，Base64 一层再返回
  const original = String(rawText || "");
  let out = "";

  if (looksLikeBase64Subscription(original)) {
    // 已经是订阅：原样返回
    out = original.trim();
  } else {
    // 不是订阅：把明文节点列表打包成 Base64 订阅
    out = toB64(original);
  }

  return {
    body: out,
    contentType: "text/plain; charset=utf-8",
  };
}
