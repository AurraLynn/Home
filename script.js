// =======================
// 背景淡入
// =======================
const bgImage = document.getElementById('bgImage');
bgImage.onload = () => { bgImage.style.opacity = 1; };

// =======================
// 卡片弹出动画
// =======================
window.addEventListener('load', () => {
    setTimeout(() => {
        document.getElementById('profileCard').classList.add('visible');
    }, 500);
});

// =======================
// 点赞逻辑
// =======================
let likeCount = Math.floor(Math.random() * 900000 + 999);
const likeTag = document.getElementById('likeTag');
const likeNum = document.getElementById('likeNum');
likeNum.textContent = likeCount;

likeTag.addEventListener('click', () => { likeAction(); });
likeTag.addEventListener('touchstart', e => { e.preventDefault(); likeAction(); }, { passive: false });

// =======================
// 随机伪作者库
// =======================
const authors = [
    "鲁迅（真没说过）",
    "莎士比亚（编的）",
    "尼采（梦里说的）",
    "苏格拉底（猜他会说）",
    "王阳明（穿越写的）",
    "弗洛伊德（梦到的）",
    "孔子（可能会笑）",
    "庄子（飘着说）",
    "李白（喝多了）",
    "爱因斯坦（灵光一闪）",
    "牛顿（苹果砸的）",
    "达芬奇（画着画着就说）",
    "歌德（吟诗中）",
    "海明威（酒杯里）",
    "马克思（梦里写稿）",
    "老子（飘着云）",
    "孙子（兵法说完了）",
    "鲁班（钉子掉了）",
    "毕加索（画疯了）",
    "达尔文（看鸟的时候）",
    "陶渊明（躺田间）",
    "爱迪生（实验没停）",
    "甄姬（宫里传出来的）",
    "妲己（眉眼含笑）",
    "杨过（神雕旁边）",
    "小龙女（石洞里）",
    "诸葛亮（草庐写的）",
    "刘备（大哥说的）",
    "曹操（心里想着）",
    "周瑜（火烧赤壁时）",
    "项羽（乌江边想）",
    "虞姬（随风而逝）",
    "白居易（诗酒间）",
    "苏轼（东坡念的）",
    "秦始皇（巡游时）",
    "汉武帝（宫里想的）",
    "刘彻（上朝间）",
    "孙悟空（花果山）",
    "猪八戒（高老庄）",
    "沙僧（流沙河）",
    "唐僧（西天路上）",
    "哪吒（莲花化身）",
    "杨戬（二郎神）",
    "貂蝉（楼台上）",
    "吕布（马上说的）",
    "关羽（青龙偃月）",
    "张飞（吼出来的）",
    "赵云（长坂坡）",
    "王昭君（出塞时）",
    "班超（西域间）",
    "李世民（贞观年间）",
    "武则天（登基说的）"
];

const quoteText = document.getElementById('quoteText');
const quoteAuthor = document.getElementById('quoteAuthor');
let gibberishTimer = null;

// =======================
// 获取鸡汤 API
// =======================
async function fetchQuoteData() {
    try {
        const res = await fetch('https://api.btstu.cn/yan/api.php?charset=utf-8&encode=json');
        const data = await res.json();
        return { text: data.text || "今日事今日毕，明日事明日盼" };
    } catch (e) {
        return { text: "鸡汤加载失败，请刷新试试。" };
    }
}

// =======================
// 获取随机字符
// =======================
function getRandomChar() {
    const chars = 'āáǎàōóǒòēéěèīíǐìūúǔùǖǘǚǜñüýÿžźżçćčñđšșț¡¿¢£¥€§©®™←→↑↓<>{}[]()!@#$%^&*~`+-=,./;:"\'\\|丶一丨丿乙乛';
    return chars[Math.floor(Math.random() * chars.length)];
}

// =======================
// 打字机 + 乱码过渡
// =======================
async function fetchQuoteWithGibberish() {
    if (gibberishTimer) clearInterval(gibberishTimer);
    quoteText.textContent = "加载中...";
    quoteAuthor.textContent = "——";

    const { text } = await fetchQuoteData();
    const randomAuthor = authors[Math.floor(Math.random() * authors.length)];

    quoteText.textContent = '';
    const displayArray = new Array(text.length).fill('');
    let currentIndex = 0;

    function showRandomChars() {
        if (currentIndex < text.length) {
            displayArray[currentIndex] = getRandomChar();
            quoteText.textContent = displayArray.join('');
            currentIndex++;
            setTimeout(showRandomChars, 100);
        } else {
            let revealIndex = 0;
            gibberishTimer = setInterval(() => {
                if (revealIndex < text.length) {
                    displayArray[revealIndex] = text[revealIndex];
                    quoteText.textContent = displayArray.join('');
                    revealIndex++;
                } else {
                    clearInterval(gibberishTimer);
                    quoteText.textContent = text;
                    quoteAuthor.textContent = "—— " + randomAuthor;
                }
            }, 50);
        }
    }
    showRandomChars();
}

// =======================
// 点赞动作
// =======================
function likeAction() {
    likeCount++;
    likeNum.textContent = likeCount;
    likeTag.classList.add('clicked');
    setTimeout(() => likeTag.classList.remove('clicked'), 300);
    fetchQuoteWithGibberish();
}

// 初始化
fetchQuoteWithGibberish();

// =======================
// 更新时间
// =======================
function updateTime() {
    const now = new Date();
    const h = now.getHours().toString().padStart(2, '0');
    const m = now.getMinutes().toString().padStart(2, '0');
    document.getElementById('time-display').textContent = `${h}:${m}`;
}
setInterval(updateTime, 1000);
updateTime();

// =======================
// 粒子效果
// =======================
const canvas = document.getElementById('particleCanvas');
const ctx = canvas.getContext('2d');
let W = canvas.width = window.innerWidth;
let H = canvas.height = window.innerHeight;
let particles = [];

class Particle {
    constructor(x, y) {
        this.x = x;
        this.y = y;
        this.r = 2 + Math.random() * 2;
        this.alpha = 0.8 + Math.random() * 0.2;
        this.speedX = (Math.random() - 0.5) * 1;
        this.speedY = (Math.random() - 0.5) * 1;
    }
    update() {
        this.x += this.speedX;
        this.y += this.speedY;
        if (this.x < 0 || this.x > W) this.speedX *= -1;
        if (this.y < 0 || this.y > H) this.speedY *= -1;
        this.alpha *= 0.995;
        return this.alpha < 0.05;
    }
    draw() {
        ctx.save();
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.r, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(255,255,255,${this.alpha})`;
        ctx.fill();
        ctx.restore();
    }
}

function createParticles(x, y) {
    for (let i = 0; i < 15; i++) particles.push(new Particle(x, y));
}

function animate() {
    ctx.clearRect(0, 0, W, H);
    for (let i = particles.length - 1; i >= 0; i--) {
        if (particles[i].update()) particles.splice(i, 1);
        else particles[i].draw();
    }
    requestAnimationFrame(animate);
}
animate();

// =======================
// 鼠标 / 触摸粒子交互
// =======================
function handleClick(e) {
    if (!e.target.closest('.quote-wrap') && !e.target.closest('.like-tag') && !e.target.closest('#time-display'))
        createParticles(e.clientX, e.clientY);
}
function handleTouch(e) {
    if (e.target.closest('.quote-wrap') || e.target.closest('.like-tag') || e.target.closest('#time-display')) return;
    e.preventDefault();
    createParticles(e.touches[0].clientX, e.touches[0].clientY);
}
document.body.addEventListener('click', handleClick);
document.body.addEventListener('touchstart', handleTouch, { passive: false });

window.addEventListener('resize', () => {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
});
