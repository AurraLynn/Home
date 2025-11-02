window.addEventListener('DOMContentLoaded', () => {

    /* ===================== 背景淡入 ===================== */
    const bgImage = document.getElementById('bgImage');
    if(bgImage){
        bgImage.onload = () => { bgImage.style.opacity = 1; };
    }

    /* ===================== 卡片弹出动画 ===================== */
    const profileCard = document.getElementById('profileCard');
    if(profileCard){
        setTimeout(() => { profileCard.classList.add('visible'); }, 500);
    }

    /* ===================== 点赞逻辑 ===================== */
    const likeTag = document.getElementById('likeTag');
    const likeNum = document.getElementById('likeNum');
    let likeCount = Math.floor(Math.random() * 900000 + 999);

    if(likeNum) likeNum.textContent = likeCount;

    function likeAction(){
        likeCount++;
        if(likeNum) likeNum.textContent = likeCount;
        if(likeTag){
            likeTag.classList.add('clicked');
            setTimeout(() => likeTag.classList.remove('clicked'), 300);
        }
        renderPoison();
    }

    if(likeTag){
        likeTag.addEventListener('click', likeAction);
        likeTag.addEventListener('touchstart', e => { e.preventDefault(); likeAction(); }, { passive: false });
    }

    /* ===================== 时间显示 ===================== */
    function updateTime(){
        const now = new Date();
        const h = now.getHours().toString().padStart(2,'0');
        const m = now.getMinutes().toString().padStart(2,'0');
        const timeEl = document.getElementById('time-display');
        if(timeEl) timeEl.textContent = `${h}:${m}`;
    }
    setInterval(updateTime, 1000);
    updateTime();

    /* ===================== 粒子效果 ===================== */
    const canvas = document.getElementById('particleCanvas');
    if(canvas){
        const ctx = canvas.getContext('2d');
        let W = canvas.width = window.innerWidth;
        let H = canvas.height = window.innerHeight;
        let particles = [];

        class Particle {
            constructor(x, y){
                this.x = x;
                this.y = y;
                this.r = 2 + Math.random()*2;
                this.alpha = 0.8 + Math.random()*0.2;
                this.speedX = (Math.random()-0.5)*1;
                this.speedY = (Math.random()-0.5)*1;
            }
            update(){
                this.x += this.speedX;
                this.y += this.speedY;
                if(this.x<0||this.x>W) this.speedX*=-1;
                if(this.y<0||this.y>H) this.speedY*=-1;
                this.alpha *= 0.995;
                return this.alpha<0.05;
            }
            draw(){
                ctx.save();
                ctx.beginPath();
                ctx.arc(this.x,this.y,this.r,0,Math.PI*2);
                ctx.fillStyle = `rgba(255,255,255,${this.alpha})`;
                ctx.fill();
                ctx.restore();
            }
        }

        function createParticles(x,y){ for(let i=0;i<15;i++) particles.push(new Particle(x,y)); }

        function animate(){
            ctx.clearRect(0,0,W,H);
            for(let i=particles.length-1;i>=0;i--){
                if(particles[i].update()){ particles.splice(i,1); }
                else { particles[i].draw(); }
            }
            requestAnimationFrame(animate);
        }
        animate();

        document.body.addEventListener('click', e=>{
            if(!e.target.closest('.quote-wrap') && !e.target.closest('.like-tag') && !e.target.closest('#time-display')){
                createParticles(e.clientX,e.clientY);
            }
        });
        document.body.addEventListener('touchstart', e=>{
            if(e.target.closest('.quote-wrap')||e.target.closest('.like-tag')||e.target.closest('#time-display')) return;
            e.preventDefault();
            createParticles(e.touches[0].clientX,e.touches[0].clientY);
        }, {passive:false});

        window.addEventListener('resize', ()=>{
            W = canvas.width = window.innerWidth;
            H = canvas.height = window.innerHeight;
        });
    }

    /* ===================== 毒鸡汤 + 乱码慢打字 ===================== */
    const poisonText = document.getElementById('hitokoto_text');
    const poisonAuthor = document.getElementById('hitokoto_author');
    let gibberishTimer = null;

    function getRandomGibberish(len){
        const chars='āáǎàōóǒòēéěèīíǐìūúǔùǖǘǚǜñüýÿžźżçćčñđšșț¡¿¢£¥€§©®™←→↑↓<>{}[]()!@#$%^&*~`+-=,./;:"\'\\|丶一丨丿乙乛';
        let s='';
        for(let i=0;i<len;i++) s+=chars[Math.floor(Math.random()*chars.length)];
        return s;
    }

    async function fetchPoison(){
        try{
            const res = await fetch("https://api.btstu.cn/yan/api.php?charset=utf-8&encode=json");
            const data = await res.json();
            const text = data.text || "今日事今日毕，明日事明日盼";
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
            const author = authors[Math.floor(Math.random()*authors.length)];
            return {text,author};
        }catch{
            return {text:"鸡汤加载失败",author:"——"};
        }
    }

    async function renderPoison(){
        if(!poisonText || !poisonAuthor) return;
        if(gibberishTimer) clearInterval(gibberishTimer);
        poisonText.textContent="加载中鸡汤...";
        poisonAuthor.textContent="——";

        const {text,author} = await fetchPoison();
        const len = text.length;
        let elapsed=0;

        gibberishTimer=setInterval(()=>{
            elapsed++;
            poisonText.textContent=getRandomGibberish(len);
            if(elapsed>=12){
                clearInterval(gibberishTimer);
                poisonText.textContent=text;
                poisonAuthor.textContent="—— "+author;
            }
        },150);
    }

    renderPoison();
    setInterval(renderPoison,50000);

});
