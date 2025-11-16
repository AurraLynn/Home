/* =========================================
 * 顶部日期：英文月份 + 中文星期
 * ========================================= */

/**
 * 更新顶部日期显示
 * - 月份：英文缩写（Jan / Feb / ...）
 * - 星期：中文（星期一 / 星期二）
 */
function updateDate() {
    const n = new Date();
    const m = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const w = ["星期日","星期一","星期二","星期三","星期四","星期五","星期六"];
    const dateDisplay = document.getElementById('dateDisplay');

    dateDisplay.innerHTML = `
        <span class="month">${m[n.getMonth()]}</span>
        <div class="right-group">
            <span>${String(n.getDate()).padStart(2,"0")}</span>
            <span>${w[n.getDay()]}</span>
        </div>
    `;
}

// 初始调用一次 + 每 24 小时更新一次
updateDate();
setInterval(updateDate, 86400000);


/* =========================================
 * 伪作者列表 & 日进度提示文案
 * ========================================= */

// 幽默“作者”列表，用于随机署名
const funnyAuthors = [
    "甄姬（宫里传出来的）",
    "鲁迅（根本没说过）",
    "诸葛亮（事后诸葛）",
    "爱因斯坦（相对来说）",
    "匿名网友（已注销）",
    "程序员（写 BUG 的时候）",
    "系统提示（来自未来）",
    "键盘侠（在线发疯中）",
    "客服小姐姐（工号已停用）",
    "宿舍楼下烧烤摊老板",
    "旁边那桌的吃瓜群众",
    "地铁广播（下一站焦虑）",
    "朋友圈文案供应商",
    "摸鱼办主任",
    "AI（但不负责任）",
    "张三（据说是内测用户）",
    "李四（已被移出群聊）",
    "王主任（正在开会中）",
    "隔壁工位的同事（不愿透露姓名）",
    "楼下奶茶店店员（加糖加料版）",
    "外卖小哥（风里雨里都在路上）",
    "保安大叔（看了很多却什么都没说）",
    "清洁阿姨（见过太多垃圾）",
    "体检中心医生（建议多喝热水）",
    "小学同桌（作业从来没自己写）",
    "隔壁小孩（被迫早熟）",
    "游戏匹配到的队友（精神状态稳定）",
    "网吧前排大神（从不回头看你一眼）",
    "聊天室房管（一键禁言了解一下）",
    "公司 HR（正在考虑中…）",
    "加班的保洁阿姨（最晚走的那位）",
    "凌晨两点的便利店店员",
    "用脚投票的用户（已经卸载）",
    "评论区首楼网友（已编辑）",
    "路人甲（镜头一闪而过）",
    "小区喇叭（天天重复那几句）",
    "手机电量 1% 时的你",
    "早八的闹钟（从未被善待过）",
    "退群前最后一句话的人",
    "工位上的盆栽（听完全部八卦）",
    "猫猫（但牠选择保持沉默）",
    "狗狗（只发表了汪汪汪声明）",
    "无名之辈（却话很多）",
    "理发店 Tony（整顿你的发型）",
    "KTV 麦霸（跑调但很自信）",
    "公交车司机（见证无数社死现场）",
    "电梯里的监控（什么都看在眼里）",
    "朋友圈仅三天可见那位朋友",
    "学校广播站台长（爱讲大道理）"
];

// 根据“今日已过百分比”显示不同提示文案
const hints = [
    [0,10,"时间是海绵里的水，挤挤总会有的"],
    [10,25,"一日之计在于晨，抓住早晨的时光"],
    [25,40,"上午时光宝贵，专注当下最重要"],
    [40,50,"不知不觉已过半，下午继续加油"],
    [50,65,"下午时光，保持精力，效率翻倍"],
    [65,75,"傍晚时分，总结一天的收获"],
    [75,85,"夜晚是思考的好时机，整理思绪"],
    [85,95,"今日即将结束，准备迎接新的一天"],
    [95,100,"今天即将过去，晚安，做个好梦"]
];


/* =========================================
 * 音乐列表 & 全局状态
 * ========================================= */

// 红心点击时从这些地址中随机播放一首
const musicList = [
    "https://save.aura.us.kg/Music/%E8%AF%8D%E4%B8%8D%E8%BE%BE%E6%84%8F%20-%20%E6%9E%97%E5%BF%86%E8%8E%B2.mp3",
    "https://save.aura.us.kg/Music/%E4%BC%8D%E7%8F%82%E7%8E%A5%20-%20%E6%B4%9B%E5%B8%8C%E6%9E%81%E9%99%90.mp3",
    "https://save.aura.us.kg/Music/%E6%B4%8B%E6%BE%9C%E4%B8%80%20-%20%E8%B0%81.mp3"
];

let currentAudio = null;      // 当前正在播放的 Audio 实例
let soundTipTimer = null;     // 控制气泡单次显示的定时器
let soundTipInterval = null;  // 控制每 30 秒弹一次的定时器

let lastProgress = 0;         // 记录最近一次计算的“今日进度百分比”


/* =========================================
 * 工具函数：点赞数 & 提示文案
 * ========================================= */

/**
 * 生成一个随机点赞数（纯视觉效果）
 */
function generateRandomLikes() {
    const min = 1299;
    const max = 999999;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

/**
 * 根据进度（0~100）获取对应的提示文案
 */
function getHintText(progress) {
    for (let i = 0; i < hints.length; i++) {
        const [min, max, text] = hints[i];
        if (progress >= min && progress < max) {
            return text;
        }
    }
    return hints[hints.length - 1][2];
}


/* =========================================
 * 顶部日进度提示气泡（跟随小星星）
 * ========================================= */

/**
 * 更新“今日进度提示气泡”的文本与位置
 */
function updateProgressHint(progress) {
    const bubble = document.getElementById('progressHintBubble');
    const bubbleText = document.getElementById('progressHintText');
    const star = document.getElementById('progressStar');
    const bottom = document.querySelector('.bottom');
    const nameBubble = document.querySelector('.name-bubble');

    if (!bubble || !bubbleText || !star || !bottom || !nameBubble) return;

    const clamped = Math.max(0, Math.min(progress, 100));
    const percentText = clamped.toFixed(1) + '%';

    bubbleText.innerHTML = `Today has passed. ${percentText}<br>${getHintText(clamped)}`;

    const starRect = star.getBoundingClientRect();
    const bottomRect = bottom.getBoundingClientRect();
    const nameRect = nameBubble.getBoundingClientRect();

    const x = starRect.left + starRect.width / 2;
    const left = x - bottomRect.left;
    const bubbleTop = nameRect.top - bottomRect.top - 50;

    bubble.style.left = `${left}px`;
    bubble.style.top = `${bubbleTop}px`;
    bubble.style.opacity = 1;
    bubble.style.transform = 'translate(-50%,0)';
}


/* =========================================
 * 日进度条（姓名气泡顶部的细进度条）
 * ========================================= */

/**
 * 根据当前时间计算今日进行的百分比，并更新：
 * - 进度条宽度
 * - 小星星位置
 * - 提示气泡
 */
function updateDayProgress() {
    const now = new Date();
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const seconds = now.getSeconds();

    const currentSeconds = hours * 3600 + minutes * 60 + seconds;
    const totalSeconds = 24 * 3600;

    const progress = (currentSeconds / totalSeconds) * 100;
    lastProgress = progress; // 记录下来，窗口变化时可复用

    const fill = document.getElementById('nameProgressFill');
    const star = document.getElementById('progressStar');
    const clamped = Math.max(0, Math.min(progress, 100));

    if (fill) fill.style.width = clamped + '%';
    if (star) star.style.left = clamped + '%';

    updateProgressHint(progress);
}


/* =========================================
 * 文本动画 & 鸡汤接口
 * ========================================= */

/**
 * 随机选一个“作者”
 */
function getRandomAuthor() {
    return funnyAuthors[Math.floor(Math.random() * funnyAuthors.length)];
}

/**
 * 打字机“乱码字符”来源
 */
function randChar() {
    const chars = "!@#……&NHL¥*^_^&*)(#@!YTB$%^&*()_+}{|:?><~`12==++**&&>?:{}|_+)(*&^%$#@%%$$##@@!!0-=[];',./";
    return chars[Math.floor(Math.random() * chars.length)];
}

/**
 * 文本打字机效果：
 * 1. 先输出一串随机乱码
 * 2. 再逐步替换为真实文字
 * 返回：预估总时长（毫秒）
 */
function animateGibberishToText(element, text) {
    const gibSpeed = 55;     // 乱码阶段速度
    const resolveSpeed = 70; // 还原阶段速度

    element.textContent = '';
    let display = '';
    let index = 0;

    function typeGib() {
        if (index < text.length) {
            display += randChar();
            element.textContent = display;
            index++;
            setTimeout(typeGib, gibSpeed);
        } else {
            let resolveIndex = 0;
            let chars = element.textContent.split('');

            function resolveNext() {
                if (resolveIndex < text.length) {
                    chars[resolveIndex] = text.charAt(resolveIndex);
                    chars.length = Math.max(chars.length, text.length);
                    element.textContent = chars.join('');
                    resolveIndex++;
                    setTimeout(resolveNext, resolveSpeed);
                }
            }
            resolveNext();
        }
    }

    typeGib();
    return text.length * (gibSpeed + resolveSpeed) + 400;
}

/**
 * 从 BTSTU 获取毒鸡汤
 */
async function fetchFromBtstu() {
    const res = await fetch("https://api.btstu.cn/yan/api.php?charset=utf-8&encode=json");
    const data = await res.json();
    return data.text || data.data || "鸡汤熬制失败了呢。☹️";
}

/**
 * 从天行获取毒鸡汤
 * 注意：key 需要替换成你自己的天行 key
 */
async function fetchFromTianapi() {
    const res = await fetch("https://apis.tianapi.com/dujitang/index?key=KEYa2d8a53cf5636e81dd87e373065fdc6c");
    const data = await res.json();

    if (data && data.code === 200 && data.result && data.result.content) {
        return data.result.content;
    }
    throw new Error("鸡汤熬干了啦。☹️");
}

/**
 * 随机选择一个接口优先调用，失败后自动切换
 */
async function fetchQuoteText() {
    const firstBtstu = Math.random() < 0.5;

    try {
        return firstBtstu ? await fetchFromBtstu() : await fetchFromTianapi();
    } catch (e1) {
        try {
            return firstBtstu ? await fetchFromTianapi() : await fetchFromBtstu();
        } catch (e2) {
            return "锅烂了啦!暂时无法熬制鸡汤😭。";
        }
    }
}

/**
 * 更新卡片内容：
 * - 显示“正在熬制中…”
 * - 拉取新鸡汤
 * - 执行“乱码 → 正文”动画
 * - 随机署名 + 点赞数
 * - 更新浏览器标题
 */
async function updateCardContent() {
    const contentElement = document.getElementById('quoteContent');
    const authorElement = document.getElementById('quoteAuthor');
    const likeCountElement = document.getElementById('likeCount');

    contentElement.textContent = "正在熬制中...";
    authorElement.textContent = "——";
    authorElement.style.opacity = "0.4";

    try {
        const quoteText = await fetchQuoteText();
        const author = getRandomAuthor();
        const likes = generateRandomLikes();

        // 修改标签页标题，显示前几字
        try {
            const maxTitleLength = 40;
            let shortQuote = quoteText;
            if (quoteText.length > maxTitleLength) {
                shortQuote = quoteText.substring(0, maxTitleLength).trim() + '…';
            }
            document.title = `Lyn's Home - ${shortQuote}`;
        } catch (err) {}

        contentElement.style.transition = "none";
        const totalDuration = animateGibberishToText(contentElement, quoteText);

        likeCountElement.textContent = likes;

        // 动画结束后淡入作者
        setTimeout(() => {
            authorElement.textContent = `—— ${author}`;
            authorElement.style.transition = "opacity 0.8s ease, text-shadow 0.8s ease";
            authorElement.style.opacity = "0.75";
        }, totalDuration);
    } catch (error) {
        contentElement.textContent = "获取内容失败，请点击刷新按钮重试";
        authorElement.textContent = "—— 系统";
        authorElement.style.opacity = "0.7";
    }
}


/* =========================================
 * 底部当前时间
 * ========================================= */

/**
 * 每秒更新一次底部时间显示
 */
function updateCurrentTime() {
    const now = new Date();
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const seconds = now.getSeconds();
    const formatted = `${String(hours).padStart(2,'0')}:${String(minutes).padStart(2,'0')}:${String(seconds).padStart(2,'0')}`;
    const currentTimeEl = document.getElementById('currentTime');
    if (currentTimeEl) {
        currentTimeEl.textContent = `Current time: ${formatted}`;
    }
}


/* =========================================
 * DOM 加载完后的初始化逻辑
 * ========================================= */

document.addEventListener('DOMContentLoaded', function() {
    // 1. 初始化日进度条 & 每分钟更新一次
    updateDayProgress();
    setInterval(updateDayProgress, 60000);

    const bottom = document.querySelector('.bottom');
    const likeButton = document.getElementById('likeButton');
    const heartIcon = likeButton ? likeButton.querySelector('i') : null;
    const floatingCard = document.querySelector('.floating-card');
    const soundTip = document.getElementById('soundTip');

    /**
     * 定位“我可是有声音的哦”气泡：
     * - 水平对齐红心中心，可微调 x 偏移
     * - 垂直放在卡片底部往下 15px，不遮挡卡片
     */
    function positionSoundTip() {
        if (!bottom || !heartIcon || !floatingCard || !soundTip) return;

        const iconRect = heartIcon.getBoundingClientRect();
        const cardRect = floatingCard.getBoundingClientRect();
        const bottomRect = bottom.getBoundingClientRect();

        // 向右偏移 60 像素（你之前调好的）
        const x = iconRect.left + iconRect.width / 2 - bottomRect.left + 60;
        const y = cardRect.bottom - bottomRect.top + 15;

        soundTip.style.left = `${x}px`;
        soundTip.style.top = `${y}px`;
    }

    /**
     * 显示“有声音”提示气泡 5 秒
     */
    function showSoundTip() {
        if (!soundTip) return;
        positionSoundTip();
        soundTip.classList.add('show');
        if (soundTipTimer) clearTimeout(soundTipTimer);
        soundTipTimer = setTimeout(() => {
            soundTip.classList.remove('show');
        }, 5000);
    }

    // 窗口尺寸变化时，重新计算两个气泡的位置
    window.addEventListener('resize', function() {
        updateProgressHint(lastProgress);
        positionSoundTip();
    });

    // 2. 初始化点赞数
    const likeCountElement = document.getElementById('likeCount');
    if (likeCountElement) {
        likeCountElement.textContent = generateRandomLikes();
    }

    // 3. 首次加载一条毒鸡汤
    updateCardContent();

    // 4. 红心点击：点赞 +1 + 播放随机音乐
    if (likeButton) {
        likeButton.addEventListener('click', function() {
            // 点赞 +1
            const likeCountElement = document.getElementById('likeCount');
            let currentLikes = parseInt(likeCountElement.textContent) || 0;
            currentLikes++;
            likeCountElement.textContent = currentLikes;

            // 红心缩放动效
            const heartIcon = this.querySelector('i');
            heartIcon.style.transform = 'scale(1.3)';
            heartIcon.style.transition = 'transform 0.3s ease';
            setTimeout(() => {
                heartIcon.style.transform = 'scale(1)';
            }, 300);

            // 随机播放音乐
            const randomUrl = musicList[Math.floor(Math.random() * musicList.length)];
            try {
                if (currentAudio) {
                    currentAudio.pause();
                    currentAudio.currentTime = 0;
                }
                currentAudio = new Audio(randomUrl);
                currentAudio.play().catch(() => {});
            } catch (e) {}
        });
    }

    // 5. 刷新按钮：旋转图标 + 换一条鸡汤
    const refreshButton = document.getElementById('refreshButton');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            const refreshIcon = this.querySelector('i');
            refreshIcon.style.transform = 'rotate(360deg)';
            refreshIcon.style.transition = 'transform 0.5s ease';
            setTimeout(() => {
                refreshIcon.style.transform = 'rotate(0)';
            }, 500);

            updateCardContent();
        });
    }

    // 6. 当前时间：初始化 + 每秒更新
    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);

    // 7. 声音气泡逻辑
    //    - 打开页面时先显示一次
    //    - 之后每 30 秒自动再提示一次
    showSoundTip();
    soundTipInterval = setInterval(showSoundTip, 30000);
});