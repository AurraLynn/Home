// 设备类型检测：如为移动端，自动跳转到 mobile.html
(function () {
    var ua = (navigator.userAgent || navigator.vendor || window.opera || "").toLowerCase();
    var isMobileDevice = /android|iphone|ipad|ipod|mobile|windows phone/i.test(ua);
    if (isMobileDevice) {
        window.location.href = "mobile.html";
    }
})();

// 顶部日期显示
function updateDate() {
    const n = new Date();
    const m = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
    const w = ["星期日","星期一","星期二","星期三","星期四","星期五","星期六"];
    const dateDisplay = document.getElementById('dateDisplay');

    if (!dateDisplay) return;

    dateDisplay.innerHTML = `
        <span class="month">${m[n.getMonth()]}</span>
        <div class="right-group">
            <span>${String(n.getDate()).padStart(2,"0")}</span>
            <span>${w[n.getDay()]}</span>
        </div>
    `;
}

updateDate();
setInterval(updateDate, 86400000);

// 随机作者列表
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

// 不同进度段的提示语
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

// 音乐列表 & 播放控制
const musicList = [
    "https://save.aura.us.kg/Music/%E8%AF%8D%E4%B8%8D%E8%BE%BE%E6%84%8F%20-%20%E6%9E%97%E5%BF%86%E8%8E%B2.mp3",
    "https://save.aura.us.kg/Music/%E4%BC%8D%E7%8F%82%E7%8E%A5%20-%20%E6%B4%9B%E5%B8%8C%E6%9E%81%E9%99%90.mp3",
    "https://save.aura.us.kg/Music/%E6%B4%8B%E6%BE%9C%E4%B8%80%20-%20%E8%B0%81.mp3"
];

let currentAudio = null;
let soundTipTimer = null;
let soundTipInterval = null;

let lastProgress = 0;

// 生成随机点赞数
function generateRandomLikes() {
    const min = 1299;
    const max = 999999;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// 根据进度获取提示文案
function getHintText(progress) {
    for (let i = 0; i < hints.length; i++) {
        const [min, max, text] = hints[i];
        if (progress >= min && progress < max) {
            return text;
        }
    }
    return hints[hints.length - 1][2];
}

// 更新顶部进度提示气泡
function updateProgressHint(progress) {
    const bubble = document.getElementById('progressHintBubble');
    const bubbleText = document.getElementById('progressHintText');
    const star = document.getElementById('progressStar');
    const bottom = document.querySelector('.bottom');
    const nameBubble = document.querySelector('.name-bubble');

    const clamped = Math.max(0, Math.min(progress, 100));
    const percentText = clamped.toFixed(1) + '%';

    if (!bubble || !bubbleText || !star || !bottom || !nameBubble) return;

    // 当前文案：英文 + 中文提示
    bubbleText.innerHTML = `Today has passed: ${percentText}<br>${getHintText(clamped)}`;

    const starRect = star.getBoundingClientRect();
    const bottomRect = bottom.getBoundingClientRect();
    const nameRect = nameBubble.getBoundingClientRect();

    const x = starRect.left + starRect.width / 2;
    const left = x - bottomRect.left;
    const bubbleTop = nameRect.top - bottomRect.top - 47;

    bubble.style.left = `${left}px`;
    bubble.style.top = `${bubbleTop}px`;
    bubble.style.opacity = 1;
    bubble.style.transform = 'translate(-50%,0)';
}

// 更新“今日已过”进度 & 进度条
function updateDayProgress() {
    const now = new Date();
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const seconds = now.getSeconds();

    const currentSeconds = hours * 3600 + minutes * 60 + seconds;
    const totalSeconds = 24 * 3600;

    const progress = (currentSeconds / totalSeconds) * 100;
    lastProgress = progress;

    const fill = document.getElementById('nameProgressFill');
    const star = document.getElementById('progressStar');
    const clamped = Math.max(0, Math.min(progress, 100));

    if (fill) fill.style.width = clamped + '%';
    if (star) star.style.left = clamped + '%';

    updateProgressHint(clamped);
}

// 取随机作者
function getRandomAuthor() {
    return funnyAuthors[Math.floor(Math.random() * funnyAuthors.length)];
}

// 乱码字符
function randChar() {
    const chars = "!@#……&NHL¥*^_^&*)(#@!YTB$%^&*()_+}{|:?><~`12==++**&&>?:{}|_+)(*&^%$#@%%$$##@@!!0-=[];',./";
    return chars[Math.floor(Math.random() * chars.length)];
}

// 先随机乱码，再逐字还原
function animateGibberishToText(element, text) {
    const gibSpeed = 55;
    const resolveSpeed = 70;

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
    const totalDuration = text.length * (gibSpeed + resolveSpeed) + 400;
    return totalDuration;
}

// API 1：BTStu
async function fetchFromBtstu() {
    const res = await fetch("https://api.btstu.cn/yan/api.php?charset=utf-8&encode=json");
    const data = await res.json();
    return data.text || data.data || "鸡汤熬制失败了呢。☹️";
}

// API 2：TianAPI（注意 key 是否正确）
async function fetchFromTianapi() {
    const res = await fetch("https://apis.tianapi.com/dujitang/index?key=KEYa2d8a53cf5636e81dd87e373065fdc6c");
    const data = await res.json();

    if (data && data.code === 200 && data.result && data.result.content) {
        return data.result.content;
    }
    throw new Error("鸡汤熬干了啦。☹️");
}

// 双 API 容错拉取鸡汤
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

// 更新卡片内容
async function updateCardContent() {
    const contentElement = document.getElementById('quoteContent');
    const authorElement = document.getElementById('quoteAuthor');
    const likeCountElement = document.getElementById('likeCount');

    if (!contentElement || !authorElement || !likeCountElement) return;

    contentElement.textContent = "正在熬制中...";
    authorElement.textContent = "——";
    authorElement.style.opacity = "0.4";

    try {
        const quoteText = await fetchQuoteText();
        const author = getRandomAuthor();
        const likes = generateRandomLikes();

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

// 更新时间显示
function updateCurrentTime() {
    const now = new Date();
    const hours = now.getHours();
    const minutes = now.getMinutes();
    const formatted = `${String(hours).padStart(2,'0')}:${String(minutes).padStart(2,'0')}`;
    const currentTimeEl = document.getElementById('currentTime');
    if (currentTimeEl) {
        currentTimeEl.textContent = `Current time: ${formatted}`;
    }
}

// DOM 加载完成逻辑
document.addEventListener('DOMContentLoaded', function() {
    updateDayProgress();
    setInterval(updateDayProgress, 60000);

    const bottom = document.querySelector('.bottom');
    const likeButton = document.getElementById('likeButton');
    const heartIcon = likeButton ? likeButton.querySelector('i') : null;
    const floatingCard = document.querySelector('.floating-card');
    const soundTip = document.getElementById('soundTip');

    // 计算“我可是有声音的哦”气泡位置（在悬浮卡片下方，指向红心）
    function positionSoundTip() {
        if (!bottom || !heartIcon || !floatingCard || !soundTip) return;

        const iconRect = heartIcon.getBoundingClientRect();
        const cardRect = floatingCard.getBoundingClientRect();
        const bottomRect = bottom.getBoundingClientRect();

        // 气泡水平位置：大致对齐红心中心，略做偏移
        const x = iconRect.left + iconRect.width / 2 - bottomRect.left + 60;

        // 气泡垂直位置：放在卡片底部往下 15 像素（完全不遮挡卡片）
        const y = cardRect.bottom - bottomRect.top + 15;

        soundTip.style.left = `${x}px`;
        soundTip.style.top = `${y}px`;
    }

    // 显示提示气泡 5 秒
    function showSoundTip() {
        if (!soundTip) return;
        positionSoundTip();
        soundTip.classList.add('show');
        if (soundTipTimer) clearTimeout(soundTipTimer);
        soundTipTimer = setTimeout(() => {
            soundTip.classList.remove('show');
        }, 5000);
    }

    window.addEventListener('resize', function() {
        // 尺寸变化时，重新计算今日进度气泡和声音提示气泡位置
        updateDayProgress();
        positionSoundTip();
    });

    const likeCountElement = document.getElementById('likeCount');
    if (likeCountElement) {
        likeCountElement.textContent = generateRandomLikes();
    }

    updateCardContent();

    if (likeButton) {
        likeButton.addEventListener('click', function() {
            // 点赞 +1
            const likeCountElement = document.getElementById('likeCount');
            let currentLikes = parseInt(likeCountElement.textContent) || 0;
            currentLikes++;
            likeCountElement.textContent = currentLikes;

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

    updateCurrentTime();
    setInterval(updateCurrentTime, 1000);

    // --- 声音气泡逻辑 ---
    // 进入页面先提示一次
    showSoundTip();
    // 之后每 30 秒弹出一次
    soundTipInterval = setInterval(showSoundTip, 30000);
});