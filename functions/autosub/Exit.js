/*
 * 文件路径：functions/autosub/Exit.js
 * 文件作用：
 *   - 作为 autosub 整体转换流程的总出口
 *   - 调用 Parser 将原始文本解析为节点列表 Node[]
 *   - 调用 Normalizer 清洗去重节点
 *   - 调用 Router 根据 client 渲染为对应订阅格式
 */

import { parseAnythingToNodes } from "./Parser.js";
import { normalizeNodes } from "./Normalizer.js";
import { routeAndRender } from "./Router.js";

/*
 * 对外导出函数：renderSubscription
 *   - 入参：
 *       - rawText：原始订阅文本（可能是混合节点、多行、base64 等）
 *       - client：目标客户端类型（clash/surge/qx/v2ray...），默认 v2ray
 *       - query/source：附加信息，用于渲染器内部参考或调试
 *   - 流程：
 *       1. parseAnythingToNodes：解析原始文本为节点数组
 *       2. normalizeNodes：对节点数组进行去重与字段归一化
 *       3. routeAndRender：根据 client 渲染为最终订阅内容
 */
export function renderSubscription(rawText, { client = "v2ray", query = {}, source = "" } = {}) {
    const nodes = parseAnythingToNodes(rawText);
    const normalized = normalizeNodes(nodes);

    return routeAndRender(normalized, {
        client,
        query,
        source,
        rawText,
    });
}