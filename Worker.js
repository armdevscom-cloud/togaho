export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIP = request.headers.get("cf-connecting-ip") || "0.0.0.0";
    const currentFeature = url.searchParams.get("feature") || "unknown";
    const nowStr = new Date().toISOString();

    // 0. 安全防線：阻擋被 BAN 的特徵碼與 IP 進站
    try {
      const isBanned = await env.DB.prepare("SELECT * FROM banned_users WHERE (target_value = ? OR target_value = ?) AND banned_until > ?").bind(currentFeature, clientIP, nowStr).first();
      if (isBanned) {
        return new Response(`<html><body style="background:#121214;color:#ff5555;text-align:center;padding-top:100px;font-family:sans-serif;"><h1>您已被系統封鎖</h1><p>到期時間：${isBanned.banned_until}</p></body></html>`, {
          headers: { "Content-Type": "text/html;charset=UTF-8" },
          status: 403
        });
      }
    } catch(e) {}

    // ----------------------------------------------------
    // 【後端 API 路由控制（對接：APIText）】
    // ----------------------------------------------------
    if (url.pathname === "/api/APIText") {
      // 處理 GET 請求：撈取貼文或管理員搜尋
      if (request.method === "GET") {
        const action = url.searchParams.get("action");
        if (action === "search") {
          const pwd = url.searchParams.get("pwd"), q = url.searchParams.get("query") || "", myF = url.searchParams.get("myFeature") || "";
          const s = await env.DB.prepare("SELECT key_value FROM admin_config WHERE key_name = 'admin_pwd'").first();
          if (!pwd || pwd !== s.key_value) return new Response(JSON.stringify({error:"密碼不正確"}), {status:401, headers:{"Content-Type":"application/json"}});
          
          // 搜尋貼文者，排除管理員自己
          const { results } = await env.DB.prepare("SELECT id,content,youtube_url,feature FROM posts WHERE feature LIKE ? AND feature != ? AND is_blocked = 0 ORDER BY id DESC").bind(`%${q}%`, myF).all();
          return new Response(JSON.stringify(results), {headers:{"Content-Type":"application/json"}});
        }
        
        // 預設撈取一般貼文
        const { results } = await env.DB.prepare("SELECT id,content,image_url,youtube_url,is_blocked,feature FROM posts WHERE is_blocked = 0 ORDER BY id DESC").all();
        return new Response(JSON.stringify(results), {headers:{"Content-Type":"application/json"}});
      }

      // 處理 POST 請求：發文、BAN人、解封、下架貼文
      if (request.method === "POST") {
        const action = url.searchParams.get("action");
        const n = await request.json();
        const s = await env.DB.prepare("SELECT key_value FROM admin_config WHERE key_name = 'admin_pwd'").first();
        
        if (action === "ban") {
          if (!n.pwd || n.pwd !== s.key_value) return new Response(JSON.stringify({error:"密碼錯誤"}), {status:401});
          let t = new Date();
          if (n.is_perm) {
            t = new Date("9999-12-31T23:59:59Z");
          } else {
            t.setDate(t.getDate() + (n.days || 0));
            t.setMonth(t.getMonth() + (n.months || 0));
            t.setFullYear(t.getFullYear() + (n.years || 0));
          }
          const r = t.toISOString();
          await env.DB.prepare("INSERT INTO banned_users (target_value, ban_type, banned_until) VALUES (?, ?, ?) ON CONFLICT(target_value) DO UPDATE SET banned_until = ?").bind(n.target, n.type, r, r).run();
          return new Response(JSON.stringify({message:`成功封鎖！期限至：${r}`}), {status:200});
        }
        
        if (action === "unban") {
          if (!n.pwd || n.pwd !== s.key_value) return new Response(JSON.stringify({error:"密碼錯誤"}), {status:401});
          await env.DB.prepare("DELETE FROM banned_users WHERE target_value = ?").bind(n.target).run();
          return new Response(JSON.stringify({message:"該使用者已成功解封！"}), {status:200});
        }
        
        if (action === "block-post") {
          if (!n.pwd || n.pwd !== s.key_value) return new Response(JSON.stringify({error:"密碼錯誤"}), {status:401});
          await env.DB.prepare("UPDATE posts SET is_blocked = 1 WHERE id = ?").bind(n.id).run();
          return new Response(JSON.stringify({message:"帖子已成功下架隱藏。"}), {status:200});
        }

        // 一般用戶發貼文邏輯
        const { content: r, image_url: o, youtube_url: c, feature: i, num1: d, num2: m, operator: u, userAnswer: l } = n;
        let p = 0; 
        if (u === "+") p = d + m;
        else if (u === "-") p = d - m;
        else if (u === "*") p = d * m;
        
        if (l !== p) return new Response(JSON.stringify({error:"驗證代碼計算不正確！"}), {status:400});
        await env.DB.prepare("INSERT INTO posts (content, image_url, youtube_url, feature) VALUES (?, ?, ?, ?)").bind(r, o, c, i).run();
        return new Response(JSON.stringify({message:"發布成功！"}), {status:200});
      }
      return new Response("Method not allowed", {status:405});
    }

    // ----------------------------------------------------
    // 【預設路由：輸出完整前端 HTML 網頁介面】
    // ----------------------------------------------------
    const html = `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>TOGAHO - TGH</title>
<style>
body{font-family:-apple-system,sans-serif;background:#121214;color:#e1e1e6;min-height:100vh;margin:0;padding:20px;box-sizing:border-box;display:flex;flex-direction:column;align-items:center}
.container{width:100%;max-width:500px}
.card{background:#202024;padding:25px;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.2);margin-bottom:20px;border:1px solid #29292e}
h1,h2,h3{color:#fff;margin-top:0}
input,select,textarea{width:100%;padding:12px;margin:8px 0;border:1px solid #29292e;border-radius:8px;box-sizing:border-box;font-size:15px;background:#121214;color:#fff}
textarea{height:80px;resize:none}
button{background:#00875f;color:#fff;border:none;width:100%;padding:12px;border-radius:8px;font-size:16px;cursor:pointer;margin-top:10px;font-weight:700}
button:hover{background:#00a372}
.math-box{background:#121214;padding:10px;border-radius:8px;margin:10px 0;font-size:16px;font-weight:700;display:flex;justify-content:center;gap:5px;border:1px solid #29292e}
.post-item{background:#202024;border:1px solid #29292e;padding:15px;border-radius:12px;margin-bottom:12px;text-align:left}
.post-text{font-size:15px;margin-bottom:8px;white-space:pre-wrap}
.post-img,.post-video{width:100%;max-height:250px;object-fit:cover;border-radius:8px;margin-top:8px}
.post-video{height:250px;border:none;background:#000}
.preview-box{background:#1a1a1e;border:1px dashed #00875f;padding:10px;border-radius:8px;margin-top:5px;display:none;text-align:center}
.preview-title{font-size:12px;color:#00875f;font-weight:700;margin-bottom:5px}
.admin-section{border-top:2px dashed #ff79c6;margin-top:40px;padding-top:20px}
.ban-btn{background:#c53030;font-size:12px;padding:6px 12px;border-radius:6px;width:auto;margin-top:5px;color:#fff;cursor:pointer;font-weight:700;border:none}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="container">
  <div class="card">
    <h1>TOGAHO (TGH)</h1>
    <form id="postForm">
      <textarea id="postContent" placeholder="今天想分享什麼貼文？" required></textarea>
      <input type="text" id="imgUrl" placeholder="圖片網址 URL（選填）">
      <input type="text" id="ytUrl" placeholder="輸入 YouTube 影片或 Shorts 短影音網址">
      <div id="videoPreviewContainer" class="preview-box">
        <div class="preview-title">🎬 YouTube 影片網頁即時預覽中：</div>
        <div id="videoPreviewPlayer"></div>
      </div>
      <div class="math-box"><span>驗證碼：</span><span id="mathQuestion">出題中...</span></div>
      <input type="number" id="mathAnswer" placeholder="請輸入答案" required>
      <input type="hidden" id="num1"><input type="hidden" id="num2"><input type="hidden" id="operator">
      <button type="submit">發布新帖子</button>
    </form>
  </div>
  <h2>最新帖子</h2>
  <div id="postList"></div>
  <div class="card admin-section">
    <h2>TGH ADMIN 管理員控制台</h2>
    <button id="unlockAdminBtn" onclick="tryUnlockAdmin()" style="background:#50fa7b;color:#282a36">🔓 點擊驗證密碼並解鎖後台</button>
    <div id="adminPanel" class="hidden">
      <h3>搜尋使用者並查看他發過的所有短片</h3>
      <input type="text" id="searchUser" placeholder="輸入使用者特徵碼搜尋...">
      <button onclick="searchUser()">搜尋並撈取短片</button>
      <div id="userSearchResults" style="margin-top:10px"></div>
      <h3 style="margin-top:20px">精準懲處懲罰 (BAN)</h3>
      <select id="banType"><option value="FEATURE">依瀏覽器特徵碼封鎖</option><option value="IP">依 IP 位址封鎖</option></select>
      <input type="text" id="banTarget" placeholder="貼上要封鎖的特徵碼或 IP">
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:5px">
        <input type="number" id="banDays" placeholder="天" value="0">
        <input type="number" id="banMonths" placeholder="月" value="0">
        <input type="number" id="banYears" placeholder="年" value="0">
        <label style="display:flex;align-items:center;font-size:12px"><input type="checkbox" id="banPerm">永久</label>
      </div>
      <button onclick="submitBan()" style="background:#c53030">執行封鎖</button>
    </div>
  </div>
</div>

<script>
let featureToken = "", savedAdminKey = "";

function generateFeatureToken() {
  if (!localStorage.getItem("tgh_feature")) {
    localStorage.setItem("tgh_feature", "TGH-" + Math.random().toString(36).substr(2, 9).toUpperCase());
  }
  featureToken = localStorage.getItem("tgh_feature");
}
generateFeatureToken();

function generateMath() {
  const e = ["+", "-", "*"], t = Math.floor(11 * Math.random()), a = Math.floor(11 * Math.random()), n = e[Math.floor(Math.random() * e.length)];
  document.getElementById("mathQuestion").innerText = t + " " + ("*" === n ? "×" : n) + " " + a + " = ?";
  document.getElementById("num1").value = t;
  document.getElementById("num2").value = a;
  document.getElementById("operator").value = n;
}
window.onload = function() { generateMath(); fetchPosts(); };

function getYouTubeId(url) {
  if (!url) return "";
  const regExp = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|\&v=|\/shorts\/)([^#\&\?]*).*/;
  const match = url.match(regExp);
  return (match && match[2].length === 11) ? match[2] : "";
}

function formatYouTubeEmbed(url) {
  const id = getYouTubeId(url);
  return id ? '<iframe class="post-video" src="https://www.youtube.com/embed/' + id + '" allowfullscreen></iframe>' : "";
}

document.getElementById("ytUrl").addEventListener("input", function() {
  const url = this.value.trim();
  const id = getYouTubeId(url);
  const box = document.getElementById("videoPreviewContainer");
  const player = document.getElementById("videoPreviewPlayer");
  if (id) {
    player.innerHTML = '<iframe class="post-video" src="https://www.youtube.com/embed/' + id + '" allowfullscreen></iframe>';
    box.style.display = "block";
  } else {
    box.style.display = "none";
  }
});

async function fetchPosts() {
  const e = await fetch("/api/APIText?feature=" + featureToken);
  if (403 === e.status) {
    document.body.innerHTML = "你已被系統封鎖。";
    return;
  }
  const t = await e.json(), a = document.getElementById("postList");
  a.innerHTML = "";
  t.forEach(function(item) {
    const div = document.createElement("div");
    div.className = "post-item";
    
    let imgTag = "";
    if (item.image_url) {
      imgTag = '<img class="post-img" src="' + item.image_url + '" alt="post image">';
    }
    
    let ytTag = formatYouTubeEmbed(item.youtube_url);
    let delBtn = savedAdminKey ? '<button class="ban-btn" onclick="blockPost(' + item.id + ')">封鎖此帖子</button>' : "";
    
    div.innerHTML = '<div class="post-text">' + item.content + '</div>' + imgTag + ytTag + '<div style="font-size:11px;color:#7c7c8a;margin-top:8px;">發布者特徵碼: ' + (item.feature || "TGH-USER") + '</div>' + delBtn;
    a.appendChild(div);
  });
}

document.getElementById("postForm").addEventListener("submit", async function(e) {
  e.preventDefault();
  const t = await fetch("/api/APIText", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      content: document.getElementById("postContent").value,
      image_url: document.getElementById("imgUrl").value.trim() || null,
      youtube_url: document.getElementById("ytUrl").value.trim() || null,
      feature: featureToken,
      num1: parseInt(document.getElementById("num1").value),
      num2: parseInt(document.getElementById("num2").value),
      operator: document.getElementById("operator").value,
      userAnswer: parseInt(document.getElementById("mathAnswer").value)
    })
  });
  if (t.ok) {
    document.getElementById("postForm").reset();
    document.getElementById("videoPreviewContainer").style.display = "none";
    generateMath(); fetchPosts();
  } else {
    const err = await t.json();
    alert("錯誤：" + err.error);
    generateMath();
  }
});

function tryUnlockAdmin() {
  const e = prompt("請輸入 TGH 管理員密碼：");
  if (e) {
    savedAdminKey = e;
    document.getElementById("adminPanel").classList.remove("hidden");
    document.getElementById("unlockAdminBtn").classList.add("hidden");
    fetchPosts();
  }
}

async function searchUser() {
  const sVal = document.getElementById("searchUser").value;
  const t = await fetch("/api/APIText?action=search&pwd=" + encodeURIComponent(savedAdminKey) + "&query=" + encodeURIComponent(sVal) + "&myFeature=" + featureToken);
  const a = await t.json(), n = document.getElementById("userSearchResults");
  if (!t.ok) { n.innerText = a.error; return; }
  n.innerHTML = a.length === 0 ? "找不到符合的使用者（已自動篩除你自身）。" : "";
  
  a.forEach(function(u) {
    const videoEmbed = formatYouTubeEmbed(u.youtube_url) || '<div style="font-size:12px;color:#888;">此貼文無影片</div>';
    n.innerHTML += '<div style="background:#121214;padding:10px;border-radius:8px;margin-top:8px;border:1px solid #333;">' +
                   '<div style="font-size:12px;color:#00875f;">使用者特徵碼: ' + u.feature + '</div>' +
                   '<div style="margin:5px 0;">貼文內容: ' + u.content + '</div>' +
                   videoEmbed +
                   '<button class="ban-btn" style="margin-top:8px;" onclick="blockPost(' + u.id + ')">直接下架這篇</button>' +
                   '<button class="ban-btn" style="background:#00875f;margin-left:5px;" onclick="unbanUser(\'' + u.feature + '\')">🔓 解除封鎖</button>' +
                   '</div>';
  });
}

async function submitBan() {
  const e = await fetch("/api/APIText?action=ban", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      pwd: savedAdminKey,
      target: document.getElementById("banTarget").value,
      type: document.getElementById("banType").value,
      days: parseInt(document.getElementById("banDays").value) || 0,
      months: parseInt(document.getElementById("banMonths").value) || 0,
      years: parseInt(document.getElementById("banYears").value) || 0,
      is_perm: document.getElementById("banPerm").checked
    })
  });
  const t = await e.json(); alert(t.message || t.error);
}

async function blockPost(e) {
  const t = await fetch("/api/APIText?action=block-post", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pwd: savedAdminKey, id: e })
  });
  if (t.ok) {
    alert("該帖子已封鎖隱藏！"); fetchPosts();
    const sVal = document.getElementById("searchUser").value;
    if (sVal) searchUser();
  } else {
    const err = await t.json(); alert(err.error);
  }
}

async function unbanUser(targetFeature) {
  const t = await fetch("/api/APIText?action=unban", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ pwd: savedAdminKey, target: targetFeature })
  });
  const data = await t.json();
  alert(data.message || data.error);
}
</script>
</body>
</html>`;

    return new Response(html, {
      headers: { "Content-Type": "text/html;charset=UTF-8" }
    });
  }
};
