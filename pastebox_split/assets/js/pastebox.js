/**
 * 文件：assets/js/pastebox.js
 * 作用：Pastebox 前端交互逻辑（已从 index.html 内联 <script> 拆分出来）
 *
 * 主要功能：
 *  - 主题切换（Light/Dark）与本地持久化
 *  - 文本编辑区：字节统计、行数统计、节点/订阅格式识别提示
 *  - 文件导入、Base64 编码/解码小工具
 *  - TTL 过期时间选择、生成链接、复制/打开
 *  - 登录/注册弹窗、用户中心（管理、删除、订阅按钮等）
 *
 * 维护建议：
 *  - 所有 DOM 元素都通过 id 获取；若你改了 HTML 的 id，这里需要同步修改
 *  - API 地址集中在 BASE_URL / API_BASE / AUTH_BASE 一段
 */// =========================
// 主题切换：读取/写入 localStorage
// =========================



    const THEME_KEY="lyn_paste_theme_v3";
    const themeToggle=document.getElementById("themeToggle");

    function applyTheme(t){
        document.body.classList.remove("theme-light","theme-dark");
        document.body.classList.add("theme-"+t);
        if(themeToggle){
            const label=themeToggle.querySelector(".label");
            if(label) label.textContent = (t==="dark" ? "Dark" : "Light");
        }
        try{localStorage.setItem(THEME_KEY,t);}catch(_){}
    }

    
// =========================
// IIFE：页面加载即执行（保持与原文件一致）
// =========================
(function(){
        let t="light";
        try{
            const s=localStorage.getItem(THEME_KEY);
            if(s==="dark"||s==="light")t=s;
        }catch(_){}
        applyTheme(t);
    })();

    themeToggle && themeToggle.addEventListener("click",()=>{
        const cur=document.body.classList.contains("theme-dark")?"dark":"light";
        applyTheme(cur==="dark"?"light":"dark");
    });

    (function(){
        const ICONS=[];
        for(let i=1;i<=10;i++)ICONS.push(`https://save.aura.us.kg/Picture/Preview/YL${i}.png`);
        const img=document.getElementById("brandIcon");
        if(img&&ICONS.length)img.src=ICONS[Math.floor(Math.random()*ICONS.length)];
    })();
// =========================
// 接口与页面基础地址（按你的部署路径 /Paste 调整）
// =========================


    const BASE_URL=location.origin+"/Paste";
    const VIEW_BASE=location.origin+"/api/paste";
    const API_BASE=location.origin+"/api/paste";
    const AUTH_BASE=location.origin+"/api/auth";
    const qs=id=>document.getElementById(id);

    const $content=qs("content");
    const $byteNum=qs("byteNum");
    const $lineCounter=qs("lineCounter");
    const $nodeInfo=qs("nodeInfo");
    const $ttlGroup=qs("ttlGroup");
    const $ttlHint=qs("ttlHint");
    const $form=qs("pasteForm");
    const $submitBtn=qs("submitBtn");
    const $resultBox=qs("resultBox");
    const $viewLinkText=qs("viewLinkText");
    const $btnCopyView=qs("btnCopyView");
    const $btnOpenView=qs("btnOpenView");
    const $btnManageFromResult=qs("btnManageFromResult");
    const $statusMsg=qs("statusMsg");
    const $baseUrlText=qs("baseUrlText");
    const $advancedSection=qs("advancedSection");
    const $ttlForeverBtn=qs("ttlForeverBtn");
    const $customId=qs("customId");
    const $customHint=qs("customHint");
    const $remark=qs("remark");
    const $fileInput=qs("fileInput");
    const $fileHint=qs("fileHint");
    const $uploadBtn=qs("uploadBtn");
    const $btnResetContent=qs("btnResetContent");

    // Base64 按钮
    const $btnBase64Encode = qs("btnBase64Encode");
    const $btnBase64Decode = qs("btnBase64Decode");

    const $btnHome=qs("btnHome");
    const $btnAuthOpen=qs("btnAuthOpen");
    const $btnAuthLabel=qs("btnAuthLabel");
    const $authModal=qs("authModal");
    const $authForm=qs("authForm");
    const $authUsername=qs("authUsername");
    const $authPassword=qs("authPassword");
    const $authRemember=qs("authRemember");
    const $btnDoLogin=qs("btnDoLogin");
    const $btnDoRegister=qs("btnDoRegister");
    const $authCloseBtn=qs("authCloseBtn");
    const $authMsg=qs("authMsg");

    const $userCenter=qs("userCenter");
    const $ucEmpty=qs("ucEmpty");
    const $ucList=qs("ucList");
    const $ucRefreshBtn=qs("ucRefreshBtn");
    const $ucLogoutBtn=qs("ucLogoutBtn");
    const $ucCloseBtn=qs("ucCloseBtn");

    if($baseUrlText)$baseUrlText.textContent=VIEW_BASE+"/{id}";

    const state={
        loggedIn:false,
        username:null,
        ttlKey:"7d",
        customSlugError:false,
        isSubmitting:false,
        mode:"create",
        originalSlug:null
    };
// =========================
// 工具函数：HTML 转义 / 日期格式化 / 统计
// =========================


    function escapeHTML(str){
        if(!str) return "";
        return String(str).replace(/[&<>"']/g,c=>({
            "&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"
        }[c]||c));
    }

    function setStatus(msg,type){
        if(!$statusMsg)return;
        $statusMsg.textContent=msg||"";
        $statusMsg.classList.remove("success","error");
        if(type)$statusMsg.classList.add(type);
    }
    function setAuthTip(msg,type){
        if(!$authMsg)return;
        $authMsg.textContent=msg||"";
        $authMsg.classList.remove("success","error");
        if(type)$authMsg.classList.add(type);
    }

    // ===== Base64 UTF-8 安全编码 / 解码 =====
// =========================
// Base64 工具：UTF-8 安全编码/解码
// =========================

    function base64EncodeUtf8(str) {
        try {
            return btoa(unescape(encodeURIComponent(str)));
        } catch (_) {
            return null;
        }
    }

    function base64DecodeUtf8(str) {
        try {
            return decodeURIComponent(escape(atob(str)));
        } catch (_) {
            return null;
        }
    }

    // ===== 节点检测 =====
// =========================
// 节点识别：检测是否包含 ss/vmess/vless/trojan/hy2 等
//（用于显示“识别到 X 条节点”提示，不改变上传内容）
// =========================

    function detectNodes(raw) {
        const text = (raw || "").trim();
        if (!text) return { isNode:false, count:0, fromBase64:false };

        const schemes = [
            "ss://","ssr://","vmess://","vless://","trojan://",
            "hysteria://","hysteria2://","hy2://","tuic://",
            "socks://","socks5://"
        ];

        function countIn(str) {
            let count = 0;
            str.split(/\r\n|\r|\n/).forEach(line => {
                const s = line.trim();
                if (!s) return;
                for (const p of schemes) {
                    if (s.startsWith(p)) {
                        count++;
                        break;
                    }
                }
            });
            return count;
        }

        let count = countIn(text);
        if (count > 0) {
            return { isNode:true, count, fromBase64:false };
        }

        // 尝试识别整段 Base64 订阅内容
        const compact = text.replace(/\s+/g,"");
        if (compact.length >= 16 && compact.length % 4 === 0 && /^[A-Za-z0-9+/=]+$/.test(compact)) {
            const decoded = base64DecodeUtf8(compact);
            if (decoded != null) {
                const c2 = countIn(decoded);
                if (c2 > 0) {
                    return { isNode:true, count:c2, fromBase64:true };
                }
            }
        }

        return { isNode:false, count:0, fromBase64:false };
    }
// =========================
// 网络请求封装：POST JSON（统一错误处理）
// =========================


    async function postJSON(url,body){
        const res=await fetch(url,{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            credentials:"include",
            body:JSON.stringify(body||{})
        });
        const data=await res.json().catch(()=>({}));
        if(!res.ok||data.ok===false){
            throw new Error(data.error||`请求失败（${res.status}）`);
        }
        return data;
    }

    function updateByteCount(){
        if(!$content||!$byteNum)return;
        let len=0;
        try{len=new TextEncoder().encode($content.value).length;}
        catch(_){len=$content.value.length;}
        $byteNum.textContent=len;

        if($lineCounter){
            const v=$content.value||"";
            const lines=v ? v.split(/\r\n|\r|\n/).length : 0;
            $lineCounter.textContent = lines+" 行";
        }

        // 节点检测
        if ($nodeInfo) {
            const info = detectNodes($content.value || "");
            if (info.isNode && info.count > 0) {
                $nodeInfo.textContent = `识别到 ${info.count} 条节点`;
                $nodeInfo.classList.add("active");
            } else {
                $nodeInfo.textContent = "";
                $nodeInfo.classList.remove("active");
            }
        }
    }
    if($content){
        updateByteCount();
        $content.addEventListener("input",updateByteCount);
    }

    if($uploadBtn&&$fileInput){
        $uploadBtn.addEventListener("click",e=>{
            e.preventDefault();
            $fileInput.click();
        });
        $fileInput.addEventListener("change",()=>{
            const file=$fileInput.files&&$fileInput.files[0];
            if(!file)return;
            const reader=new FileReader();
            reader.onload=()=>{
                if($content){
                    $content.value=reader.result||"";
                    updateByteCount();
                }
                if($fileHint){
                    $fileHint.textContent=`已加载：${file.name}（${file.size} 字节）`;
                    $fileHint.classList.remove("hint-error");
                    $fileHint.classList.add("hint-success");
                }
                setStatus(`已从文件「${file.name}」加载内容。`,"success");
            };
            reader.onerror=()=>{
                if($fileHint){
                    $fileHint.textContent="读取文件失败，请确认是文本文件。";
                    $fileHint.classList.remove("hint-success");
                    $fileHint.classList.add("hint-error");
                }
                setStatus("读取文件失败，请确认是文本文件。","error");
            };
            reader.readAsText(file);
        });
    }

    if($btnResetContent){
        $btnResetContent.addEventListener("click",()=>{
            if($content)$content.value="";
            if($remark)$remark.value="";
            updateByteCount();
            setStatus("已重置输入。");
        });
    }

    // Base64 编码
    if ($btnBase64Encode) {
        $btnBase64Encode.addEventListener("click", () => {
            if (!$content) return;
            const v = $content.value;
            if (!v) {
                setStatus("没有可编码的内容。", "error");
                return;
            }
            const encoded = base64EncodeUtf8(v);
            if (encoded == null) {
                setStatus("Base64 编码失败，内容可能包含不支持的字符。", "error");
                return;
            }
            $content.value = encoded;
            updateByteCount();
            setStatus("已使用 Base64 编码当前内容。", "success");
        });
    }

    // Base64 解码 + 按钮高亮
    if ($btnBase64Decode) {
        $btnBase64Decode.addEventListener("click", () => {
            if (!$content) return;
            const v = $content.value;
            if (!v) {
                setStatus("没有可解码的内容。", "error");
                return;
            }
            const decoded = base64DecodeUtf8(v);
            if (decoded == null) {
                setStatus("Base64 解码失败，文本可能不是合法的 Base64。", "error");
                return;
            }
            $content.value = decoded;
            updateByteCount();
            setStatus("已使用 Base64 解码当前内容。", "success");

            $btnBase64Decode.classList.add("decode-active");
            setTimeout(() => {
                $btnBase64Decode.classList.remove("decode-active");
            }, 300);
        });
    }

    const ttlText={
        "10m":"内容将在 10 分钟后过期。",
        "1d":"内容将在 1 天后过期。",
        "7d":"内容将在 7 天后过期。",
        "30d":"内容将在 30 天后过期。",
        "forever":"内容不会自动过期（后台清理除外）。"
    };
    function setTtl(key){
        state.ttlKey=key;
        if($ttlGroup){
            $ttlGroup.querySelectorAll(".ttl-btn").forEach(b=>{
                b.classList.toggle("active",b.dataset.ttl===key);
            });
        }
        if($ttlHint)$ttlHint.textContent=ttlText[key]||ttlText["7d"];
    }
    setTtl("7d");
    if($ttlGroup){
        $ttlGroup.addEventListener("click",e=>{
            const btn=e.target.closest(".ttl-btn");
            if(!btn)return;
            if(btn.disabled)return;
            const key=btn.dataset.ttl;
            if(!key)return;
            setTtl(key);
        });
    }

    function validateCustomSlug(){
        state.customSlugError=false;
        if(!$customId)return;
        const val=$customId.value.trim();
        if(!state.loggedIn){
            if($advancedSection)$advancedSection.style.display="none";
            return;
        }else{
            if($advancedSection)$advancedSection.style.display="";
        }
        if(!val){
            if($customHint){
                $customHint.textContent="留空则自动分配随机 ID。";
                $customHint.classList.remove("hint-error","hint-success");
            }
            $customId.classList.remove("input-error");
            return;
        }
        const ok=/^[A-Za-z0-9_-]+$/.test(val);
        if(!ok){
            state.customSlugError=true;
            if($customHint){
                $customHint.textContent="仅支持A-Za-z0-9_- 。";
                $customHint.classList.add("hint-error");
                $customHint.classList.remove("hint-success");
            }
            $customId.classList.add("input-error");
        }else{
            if($customHint){
                $customHint.textContent="可以使用这个自定义 ID。";
                $customHint.classList.remove("hint-error");
                $customHint.classList.add("hint-success");
            }
            $customId.classList.remove("input-error");
        }
    }
    if($customId)$customId.addEventListener("input",validateCustomSlug);

    function enterCreateMode(clear){
        state.mode="create";
        state.originalSlug=null;
        if($submitBtn){
            const span=$submitBtn.querySelector(".text");
            if(span)span.textContent="上传";
        }
        if($btnHome)$btnHome.style.display="none";
        if(clear){
            if($content)$content.value="";
            if($remark)$remark.value="";
            if($customId)$customId.value="";
            updateByteCount();
            setStatus("");
        }
    }

    if($btnHome){
        $btnHome.addEventListener("click",()=>{
            enterCreateMode(true);
            history.replaceState(null,"",BASE_URL);
            window.scrollTo({top:0,behavior:"smooth"});
        });
    }

    function applyAuthUI(){
        if($btnAuthLabel){
            $btnAuthLabel.textContent = state.loggedIn ? (state.username || "用户") : "LogIn";
        }

        if($advancedSection){
            $advancedSection.style.display = state.loggedIn ? "" : "none";
        }

        if ($ttlForeverBtn) {
            if (state.loggedIn) {
                $ttlForeverBtn.disabled = false;
            } else {
                $ttlForeverBtn.disabled = true;
                if (state.ttlKey === "forever") {
                    setTtl("7d");
                }
            }
        }

        validateCustomSlug();
    }

    function setLoggedIn(username){
        state.loggedIn = true;
        state.username = username || "用户";
        try { localStorage.setItem("pbx_username", state.username); } catch(_) {}

        // 登录后默认改为 Never
        setTtl("forever");

        applyAuthUI();
    }
    function setLoggedOut(){
        state.loggedIn=false;
        state.username=null;
        try{localStorage.removeItem("pbx_username");}catch(_){}
        applyAuthUI();
    }

    async function initAuthFromServer(){
        let saved=null;
        try{saved=localStorage.getItem("pbx_username")||null;}catch(_){}
        try{
            const res=await fetch(location.origin+"/api/me/pastes",{credentials:"include"});
            if(res.status===401){setLoggedOut();return;}
            const data=await res.json().catch(()=>({}));
            if(data&&data.ok){
                setLoggedIn(saved||"用户");
            }else{
                setLoggedOut();
            }
        }catch(_){
            setLoggedOut();
        }
    }
// =========================
// 登录/注册弹窗：打开/关闭/提示/状态同步
// =========================


    function openAuthModal(){
        if(!$authModal)return;
        $authModal.style.display="flex";
        setAuthTip("");
        if($authUsername)$authUsername.focus();
    }
    function closeAuthModal(){
        if(!$authModal)return;
        $authModal.style.display="none";
        if($authForm)$authForm.reset();
        if($authRemember) $authRemember.checked = true;
        setAuthTip("");
    }
    if($authCloseBtn)$authCloseBtn.addEventListener("click",closeAuthModal);
    if($authModal){
        $authModal.addEventListener("click",e=>{
            if(e.target===$authModal)closeAuthModal();
        });
    }

    function openUserCenter(){
        if(!$userCenter)return;
        $userCenter.style.display="flex";
        loadUserPastes();
    }
    function closeUserCenter(){
        if(!$userCenter)return;
        $userCenter.style.display="none";
    }
    if($ucCloseBtn)$ucCloseBtn.addEventListener("click",closeUserCenter);
    if($userCenter){
        $userCenter.addEventListener("click",e=>{
            if(e.target===$userCenter)closeUserCenter();
        });
    }

    if($btnAuthOpen){
        $btnAuthOpen.addEventListener("click",()=>{
            if(state.loggedIn)openUserCenter();
            else openAuthModal();
        });
    }

    if($authForm){
        $authForm.addEventListener("submit",async e=>{
            e.preventDefault();
            const u=$authUsername.value.trim();
            const p=$authPassword.value;
            const remember = $authRemember ? $authRemember.checked : true;

            if(!u||!p){
                setAuthTip("用户名和密码不能为空。","error");
                return;
            }
            setAuthTip("登录中…");
            try{
                const data=await postJSON(AUTH_BASE+"/login",{
                    username:u,
                    password:p,
                    remember
                });
                setLoggedIn(data.username||u);
                setAuthTip("登录成功。","success");
                setTimeout(closeAuthModal,300);
            }catch(err){
                setAuthTip(err.message||"登录失败。","error");
            }
        });
    }
    if($btnDoRegister){
        $btnDoRegister.addEventListener("click",async ()=>{
            const u=$authUsername.value.trim();
            const p=$authPassword.value;
            if(!u||!p){setAuthTip("请先填写用户名和密码。","error");return;}
            if(p.length<6){setAuthTip("密码至少 6 位。","error");return;}
            setAuthTip("注册中…");
            try{
                await postJSON(AUTH_BASE+"/register",{username:u,password:p});
                setAuthTip("注册成功，请点击登录。","success");
            }catch(err){
                setAuthTip(err.message||"注册失败。","error");
            }
        });
    }

    function formatDate(d){
        if(!d)return"-";
        const dt=new Date(d);
        if(Number.isNaN(dt.getTime()))return"-";
        const y=dt.getFullYear();
        const m=String(dt.getMonth()+1).padStart(2,"0");
        const da=String(dt.getDate()).padStart(2,"0");
        const h=String(dt.getHours()).padStart(2,"0");
        const mi=String(dt.getMinutes()).padStart(2,"0");
        return `${y}-${m}-${da} ${h}:${mi}`;
    }
    function calcRemainDays(expires){
        if(!expires)return null;
        const t=new Date(expires).getTime();
        if(Number.isNaN(t))return null;
        const now=Date.now();
        const diff=t-now;
        const d=Math.ceil(diff/86400000);
        return d;
    }

    // 订阅链接拼接
    function buildSubLink(slug, clientKey) {
        const base = `${location.origin}/api/sub?id=${encodeURIComponent(slug)}`;
        if (!clientKey || clientKey === "general") return base;
        return `${base}&client=${encodeURIComponent(clientKey)}`;
    }

    // ===== 订阅选择面板逻辑 =====
    let currentSubSlug = null;
// =========================
// 订阅客户端选择：弹出面板、构造订阅链接、复制
// =========================


    function openSubClientMenu(slug) {
        currentSubSlug = slug;
        const overlay = document.getElementById("subClientOverlay");
        if (overlay) overlay.style.display = "flex";
    }

    function closeSubClientMenu() {
        currentSubSlug = null;
        const overlay = document.getElementById("subClientOverlay");
        if (overlay) overlay.style.display = "none";
    }

    (function initSubClientMenu(){
        const overlay = document.getElementById("subClientOverlay");
        if (!overlay) return;

        const closeBtn = document.getElementById("subMenuCloseBtn");
        if (closeBtn) closeBtn.addEventListener("click", closeSubClientMenu);

        overlay.addEventListener("click",(e)=>{
            if (e.target === overlay) closeSubClientMenu();
        });

        overlay.querySelectorAll(".sub-menu-btn").forEach(btn=>{
            btn.addEventListener("click", async ()=>{
                if (!currentSubSlug) return;
                const clientKey = btn.getAttribute("data-client") || "general";
                const url = buildSubLink(currentSubSlug, clientKey);

                try{
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        await navigator.clipboard.writeText(url);
                        setStatus(`已复制 ${btn.textContent.trim()} 订阅链接。`, "success");
                    } else {
                        window.prompt("复制订阅链接：", url);
                    }
                }catch(_){
                    window.prompt("复制失败，可手动复制以下链接：", url);
                }
                closeSubClientMenu();
            });
        });
    })();
// =========================
// 用户中心：拉取列表、渲染条目、绑定按钮事件
// =========================


    async function loadUserPastes(){
        if(!$ucEmpty||!$ucList)return;
        $ucEmpty.style.display="";
        $ucEmpty.textContent="正在加载你的记录…";
        $ucList.style.display="none";
        $ucList.innerHTML="";
        try{
            const res=await fetch(location.origin+"/api/me/pastes",{credentials:"include"});
            if(res.status===401){
                $ucEmpty.textContent="登录状态已失效，请重新登录。";
                setLoggedOut();
                return;
            }
            const data=await res.json().catch(()=>({}));
            if(!data.ok){
                $ucEmpty.textContent=data.error||"加载失败。";
                return;
            }
            const items=data.items||[];
            if(!items.length){
                $ucEmpty.textContent="暂无记录，先去创建一条吧。";
                return;
            }

            const valid=[];
            await Promise.all(items.map(async (item)=>{
                const slug=item.slug||item.id;
                if(!slug)return;
                try{
                    const u=new URL(`${API_BASE}/${encodeURIComponent(slug)}`);
                    u.searchParams.set("manage","1");
                    const r=await fetch(u.toString(),{credentials:"include"});
                    if(!r.ok)return;
                    const d=await r.json().catch(()=>null);
                    if(!d||d.ok===false)return;
                    const remain=calcRemainDays(d.expiresAt);
                    if(remain!=null && remain<0)return;

                    d._nodeInfo = detectNodes(d.content || "");
                    valid.push(d);
                }catch(_){}
            }));

            if(!valid.length){
                $ucEmpty.style.display="";
                $ucEmpty.textContent="暂无有效记录（过期或已删除）。";
                return;
            }

            valid.sort((a,b)=>(b.createdAt||0)-(a.createdAt||0));

            $ucEmpty.style.display="none";
            $ucList.style.display="flex";

            valid.forEach(d=>{
                const slug=d.slug;
                if(!slug)return;
                const remark=d.remark||"(无备注)";
                const created=d.createdAt||null;
                const expires=d.expiresAt||null;
                const ttlKey=d.ttlKey||"";

                const viewUrl=`${VIEW_BASE}/${encodeURIComponent(slug)}`;
                const remain=calcRemainDays(expires);

                const nodeInfo = d._nodeInfo || detectNodes(d.content || "");
                const hasNode = !!nodeInfo.isNode && nodeInfo.count > 0;
                const nodeCount = nodeInfo.count || 0;

                const row=document.createElement("div");
                row.className="uc-item";
                row.innerHTML=`
                    <div class="uc-item-top">
                        <div class="uc-item-title">
                            <span class="uc-remark-tag">${escapeHTML(remark)}</span>
                            <span class="uc-slug-tag">${escapeHTML(slug)}</span>
                        </div>
                        <div class="uc-item-meta"></div>
                    </div>
                    <div class="uc-link-row">
                        <span class="uc-link-tag">${escapeHTML(viewUrl)}</span>
                    </div>
                    <div class="uc-item-actions"></div>
                `;
                const meta=row.querySelector(".uc-item-meta");
                const act=row.querySelector(".uc-item-actions");
                const titleBox=row.querySelector(".uc-item-title");

                // 只显示到期信息（去掉创建时间）
                let metaText="";
                if(!expires || ttlKey==="forever"){
                    metaText=`到期：Never🙌`;
                }else{
                    metaText+=`到期：${formatDate(expires)}`;
                    if(remain!=null && remain>=0){
                        metaText+=` · 自动清除还有 ${remain} 天`;
                    }
                }
                meta.textContent=metaText;

                // 节点订阅按钮
                if (hasNode && titleBox) {
                    const subBtn=document.createElement("button");
                    subBtn.type="button";
                    subBtn.className="uc-sub-btn";
                    subBtn.textContent = nodeCount > 0 ? `订阅(${nodeCount})` : "订阅";
                    subBtn.addEventListener("click",()=>openSubClientMenu(slug));
                    titleBox.appendChild(subBtn);
                }

                const btnEdit=document.createElement("button");
                btnEdit.type="button";
                btnEdit.className="btn-secondary btn-xs";
                btnEdit.innerHTML = `
    <span class="icon-svg">
        <svg t="1765114666854" class="icon" viewBox="0 0 1024 1024" version="1.1"
             xmlns="http://www.w3.org/2000/svg" p-id="34010" width="200" height="200">
            <path d="M772.8 928H491.2c-86.4 0-155.2-70.4-155.2-155.2v-46.4c0-86.4 70.4-155.2 155.2-155.2h281.6c86.4 0 155.2 70.4 155.2 155.2v46.4c0 84.8-70.4 155.2-155.2 155.2z" fill="#96E8BA" p-id="34011"></path>
            <path d="M720 851.2H272c-62.4 0-113.6-46.4-113.6-104V241.6c0-57.6 51.2-104 113.6-104h235.2c12.8 0 22.4 9.6 22.4 22.4s-9.6 22.4-22.4 22.4H272c-38.4 0-68.8 27.2-68.8 59.2v504c0 32 30.4 59.2 68.8 59.2h448c38.4 0 68.8-27.2 68.8-59.2V326.4c0-12.8 9.6-22.4 22.4-22.4s22.4 9.6 22.4 22.4v419.2c0 57.6-51.2 105.6-113.6 105.6z" fill="#103E26" p-id="34012"></path>
            <path d="M526.4 376c-6.4 0-11.2-1.6-16-6.4-8-9.6-8-22.4 1.6-32L793.6 70.4c9.6-8 22.4-8 32 1.6 8 9.6 8 22.4-1.6 32L542.4 369.6c-4.8 4.8-9.6 6.4-16 6.4zM688 446.4H320c-12.8 0-22.4-9.6-22.4-22.4s9.6-22.4 22.4-22.4h368c12.8 0 22.4 9.6 22.4 22.4s-9.6 22.4-22.4 22.4zM688 574.4H320c-12.8 0-22.4-9.6-22.4-22.4s9.6-22.4 22.4-22.4h368c12.8 0 22.4 9.6 22.4 22.4s-9.6 22.4-22.4 22.4zM688 686.4H320c-12.8 0-22.4-9.6-22.4-22.4s9.6-22.4 22.4-22.4h368c12.8 0 22.4 9.6 22.4 22.4s-9.6 22.4-22.4 22.4z" fill="#103E26" p-id="34013"></path>
        </svg>
    </span>
    编辑
`;
                btnEdit.addEventListener("click",()=>{
                    closeUserCenter();
                    enterEditMode(slug);
                });

                const btnCopy=document.createElement("button");
                btnCopy.type="button";
                btnCopy.className="btn-secondary btn-xs";
                btnCopy.innerHTML=`<span class="icon-svg">
    <svg t="1765114342950" class="icon" viewBox="0 0 1024 1024" version="1.1"
         xmlns="http://www.w3.org/2000/svg" p-id="27399" width="200" height="200">
        <path d="M640 512h256c71.68 0 128 56.32 128 128v256c0 71.68-56.32 128-128 128h-256c-71.68 0-128-56.32-128-128v-256c0-71.68 56.32-128 128-128z" fill="#5AC8FA" p-id="27400"></path>
        <path d="M230.4 665.6c15.36 0 25.6 10.24 25.6 25.6s-10.24 25.6-25.6 25.6h-102.4C56.32 716.8 0 660.48 0 588.8v-460.8C0 56.32 56.32 0 128 0h460.8C660.48 0 716.8 56.32 716.8 128v102.4c0 15.36-10.24 25.6-25.6 25.6s-25.6-10.24-25.6-25.6v-102.4c0-40.96-35.84-76.8-76.8-76.8h-460.8C87.04 51.2 51.2 87.04 51.2 128v460.8c0 40.96 35.84 76.8 76.8 76.8h102.4z m204.8-307.2C394.24 358.4 358.4 394.24 358.4 435.2v460.8c0 40.96 35.84 76.8 76.8 76.8h460.8c40.96 0 76.8-35.84 76.8-76.8v-460.8c0-40.96-35.84-76.8-76.8-76.8h-460.8z m0-51.2h460.8C967.68 307.2 1024 363.52 1024 435.2v460.8c0 71.68-56.32 128-128 128h-460.8C363.52 1024 307.2 967.68 307.2 896v-460.8C307.2 363.52 363.52 307.2 435.2 307.2z" fill="" p-id="27401"></path>
    </svg>
</span>Copy`
                btnCopy.addEventListener("click",async ()=>{
                    try{
                        await navigator.clipboard.writeText(viewUrl);
                        setStatus("已复制链接。","success");
                    }catch(_){
                        setStatus("复制失败，请手动复制。","error");
                    }
                });

                const btnOpen=document.createElement("button");
                btnOpen.type="button";
                btnOpen.className="btn-secondary btn-xs";
                btnOpen.innerHTML = `
                                    <span class="icon-svg">
                    <svg t="1765114153666" class="icon" viewBox="0 0 1024 1024" version="1.1"
                         xmlns="http://www.w3.org/2000/svg" p-id="24070" width="200" height="200">
                        <path d="M512 989.866667C248.081067 989.866667 34.133333 775.918933 34.133333 512S248.081067 34.133333 512 34.133333s477.866667 213.947733 477.866667 477.866667-213.947733 477.866667-477.866667 477.866667z m0-68.266667c226.2016 0 409.6-183.3984 409.6-409.6S738.2016 102.4 512 102.4 102.4 285.7984 102.4 512s183.3984 409.6 409.6 409.6z" fill="#369335" p-id="24071"></path>
                        <path d="M439.6032 439.6032l-72.430933 217.224533 217.224533-72.430933 48.298667 48.298667L270.6432 753.322667l120.661333-362.052267 48.298667 48.298667z m0 0l-48.298667-48.298667L753.3568 270.677333l-120.661333 362.052267-48.298667-48.298667 72.430933-217.224533-217.224533 72.430933z" fill="#369335" p-id="24072"></path>
                        <path d="M512 512m-34.133333 0a34.133333 34.133333 0 1 0 68.266666 0 34.133333 34.133333 0 1 0-68.266666 0Z" fill="#369335" p-id="24073"></path>
                    </svg>
                </span>
                Open
            `;
                btnOpen.addEventListener("click",()=>{window.open(viewUrl,"_blank","noopener");});

                const btnDel=document.createElement("button");
                btnDel.type="button";
                btnDel.className="btn-danger btn-xs";
                btnDel.innerHTML =`
    <span class="icon-svg">
        <svg t="1765114587958" class="icon" viewBox="0 0 1024 1024" version="1.1"
             xmlns="http://www.w3.org/2000/svg" p-id="30200" width="200" height="200">
            <path d="M512 512m-512 0a512 512 0 1 0 1024 0 512 512 0 1 0-1024 0Z" fill="#FDEBED" p-id="30201"></path>
            <path d="M729.6 384H294.4c-7.68 0-12.8-5.12-12.8-12.8v-25.6c0-7.68 5.12-12.8 12.8-12.8h115.2v-25.6c0-14.08 11.52-25.6 25.6-25.6h153.6c14.08 0 25.6 11.52 25.6 25.6v25.6h115.2c7.68 0 12.8 5.12 12.8 12.8v25.6c0 7.68-5.12 12.8-12.8 12.8z m-371.2 38.4h307.2c28.16 0 51.2 23.04 51.2 51.2v217.6c0 28.16-23.04 51.2-51.2 51.2H358.4c-28.16 0-51.2-23.04-51.2-51.2V473.6c0-28.16 23.04-51.2 51.2-51.2z m192 243.2c0 7.68 5.12 12.8 12.8 12.8s12.8-5.12 12.8-12.8V537.6c0-7.68-5.12-12.8-12.8-12.8s-12.8 5.12-12.8 12.8v128z m-102.4 0c0 7.68 5.12 12.8 12.8 12.8s12.8-5.12 12.8-12.8V537.6c0-7.68-5.12-12.8-12.8-12.8s-12.8 5.12-12.8 12.8v128z" fill="#EC3A4E" p-id="30202"></path>
        </svg>
    </span>
    删除
`;
                btnDel.addEventListener("click",async ()=>{
                    if(!confirm("确认删除该链接？"))return;
                    try{
                        await postJSON(API_BASE,{action:"delete",slug});
                        loadUserPastes();
                        setStatus("已删除。","success");
                    }catch(err){
                        setStatus(err.message||"删除失败。","error");
                    }
                });

                act.appendChild(btnEdit);
                act.appendChild(btnCopy);
                act.appendChild(btnOpen);
                act.appendChild(btnDel);

                $ucList.appendChild(row);
            });
        }catch(err){
            $ucEmpty.style.display="";
            $ucEmpty.textContent=err.message||"加载失败。";
        }
    }

    if($ucRefreshBtn)$ucRefreshBtn.addEventListener("click",loadUserPastes);
    if($ucLogoutBtn){
        $ucLogoutBtn.addEventListener("click",async ()=>{
            try{await postJSON(AUTH_BASE+"/logout",{});}catch(_){}
            setLoggedOut();
            closeUserCenter();
            enterCreateMode(true);
            setStatus("已退出登录。","success");
        });
    }

    async function enterEditMode(slug){
        state.mode="edit";
        state.originalSlug=slug;
        if($submitBtn){
            const span=$submitBtn.querySelector(".text");
            if(span)span.textContent="更新";
        }
        if($btnHome)$btnHome.style.display="inline-flex";
        setStatus("正在载入内容…");
        try{
            const url=new URL(`${API_BASE}/${encodeURIComponent(slug)}`);
            url.searchParams.set("manage","1");
            const res=await fetch(url.toString(),{credentials:"include"});
            const data=await res.json().catch(()=>({}));
            if(!res.ok||data.ok===false){
                throw new Error(data.error||"内容不存在。");
            }
            if($content)$content.value=data.content||"";
            if($remark)$remark.value=data.remark||"";
            if($customId){
                $customId.value=data.slug||slug;
                $customId.readOnly=false;
            }
            updateByteCount();
            if(data.ttlKey)setTtl(data.ttlKey);
            const urlClean=new URL(location.href);
            urlClean.searchParams.set("id",slug);
            history.replaceState(null,"",urlClean.toString());
            setStatus("已进入编辑模式。","success");
        }catch(err){
            setStatus(err.message||"载入失败。","error");
            enterCreateMode(false);
        }
    }

    function showResultLink(slug){
        if(!$resultBox||!$viewLinkText)return;
        const url=`${VIEW_BASE}/${encodeURIComponent(slug)}`;
        $viewLinkText.textContent=url;
        $resultBox.style.display="block";
        if($btnManageFromResult){
            $btnManageFromResult.style.display = state.loggedIn ? "inline-flex" : "none";
        }
    }

    if($btnCopyView){
        $btnCopyView.addEventListener("click",async ()=>{
            const text=$viewLinkText&&$viewLinkText.textContent;
            if(!text)return;
            try{
                await navigator.clipboard.writeText(text);
                setStatus("访问链接已复制。","success");
            }catch(_){
                setStatus("复制失败，请手动复制。","error");
            }
        });
    }
    if($btnOpenView){
        $btnOpenView.addEventListener("click",()=>{
            const text=$viewLinkText&&$viewLinkText.textContent;
            if(!text)return;
            window.open(text,"_blank","noopener");
        });
    }
    if($btnManageFromResult){
        $btnManageFromResult.addEventListener("click",()=>{
            if(!state.loggedIn){
                openAuthModal();
                return;
            }
            openUserCenter();
        });
    }

    if($form){
        $form.addEventListener("submit",async e=>{
            e.preventDefault();
            const text=($content&&$content.value.trim())||"";
            if(!text){setStatus("内容不能为空。","error");return;}
            if(state.customSlugError){setStatus("自定义 URL 不合法。","error");return;}

            let slug=null;
            let newSlug=null;
            if(state.mode==="edit"){
                slug=state.originalSlug;
                if($customId){
                    const v=$customId.value.trim();
                    if(v&&v!==slug)newSlug=v;
                }
            }else{
                if(state.loggedIn&&$customId){
                    const v=$customId.value.trim();
                    if(v)slug=v;
                }
            }

            const payload={
                action:state.mode==="edit"?"update":"create",
                content:text,
                ttlKey:state.ttlKey,
                remark:$remark?$remark.value.trim():""
            };
            if(slug)payload.slug=slug;
            if(newSlug)payload.newSlug=newSlug;

            state.isSubmitting=true;
            if($submitBtn){
                $submitBtn.disabled=true;
                $submitBtn.classList.add("btn-disabled");
                const span=$submitBtn.querySelector(".text");
                if(span)span.textContent=state.mode==="edit"?"保存中…":"上传中…";
            }
            setStatus("正在提交…");
            try{
                const data=await postJSON(API_BASE,payload);
                const finalSlug=data.slug||newSlug||slug;
                if(!finalSlug)throw new Error("返回数据缺少 slug。");
                showResultLink(finalSlug);

                setStatus(state.mode==="edit"?"更新成功，已回到主页。":"上传完成，已生成链接。","success");
                enterCreateMode(true);
            }catch(err){
                setStatus(err.message||"操作失败。","error");
            }finally{
                state.isSubmitting=false;
                if($submitBtn){
                    $submitBtn.disabled=false;
                    $submitBtn.classList.remove("btn-disabled");
                    const span=$submitBtn.querySelector(".text");
                    if(span)span.textContent=state.mode==="edit"?"更新":"上传";
                }
            }
        });
    }

    if($baseUrlText)$baseUrlText.textContent=VIEW_BASE+"/{id}";

    document.addEventListener("keydown",e=>{
        if(e.key==="Escape"){
            const overlay = document.getElementById("subClientOverlay");
            if(overlay && overlay.style.display==="flex"){
                closeSubClientMenu();
                return;
            }
            if($userCenter&&$userCenter.style.display==="flex")closeUserCenter();
            else if($authModal&&$authModal.style.display==="flex")closeAuthModal();
        }
    });

    (async
// =========================
// 页面初始化：绑定事件（输入、TTL、上传、复制等）
// =========================
 function init(){
        await initAuthFromServer();
        applyAuthUI();
    })();