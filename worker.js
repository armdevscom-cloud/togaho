export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIP = request.headers.get("cf-connecting-ip") || "0.0.0.0";
    const nowStr = new Date().toISOString();

    // 0. 安全防線：IP 封鎖檢查
    try {
      const isBanned = await env.DB.prepare("SELECT * FROM banned_users WHERE target_value = ? AND banned_until > ?").bind(clientIP, nowStr).first();
      if (isBanned) {
        return new Response("<html><body style='background:#000;color:#ff5555;text-align:center;padding-top:100px;font-family:sans-serif;'><h1>帳號或 IP 已被系統封鎖</h1><p>到期時間：" + isBanned.banned_until + "</p></body></html>", {
          headers: { "Content-Type": "text/html;charset=UTF-8" },
          status: 403
        });
      }
    } catch(e) {}

    // ----------------------------------------------------
    // 【後端 API 路由】
    // ----------------------------------------------------
    if (url.pathname.startsWith("/api/")) {
      
      // 註冊
      if (url.pathname === "/api/register" && request.method === "POST") {
        const { username, password } = await request.json();
        if (!username || !password) return new Response(JSON.stringify({error:"請輸入帳號與密碼"}), {status:400});
        try {
          const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
          const passwordHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
          const userCount = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users").first();
          const role = (userCount.cnt === 0 || username === "admin") ? "admin" : "user";
          const defaultAvatar = "https://picsum.photos/200";

          await env.DB.prepare("INSERT INTO users (username, password_hash, role, avatar_url, bio) VALUES (?, ?, ?, ?, ?)").bind(username, passwordHash, role, defaultAvatar, "這人很懶，什麼都沒有留下...").run();
          return new Response(JSON.stringify({message:"註冊成功"}), {status:200});
        } catch(e) {
          return new Response(JSON.stringify({error:"帳號已被註冊"}), {status:400});
        }
      }

      // 登入
      if (url.pathname === "/api/login" && request.method === "POST") {
        const { username, password } = await request.json();
        const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
        const passwordHash = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
        const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? AND password_hash = ?").bind(username, passwordHash).first();
        if (!user) return new Response(JSON.stringify({error:"帳號或密碼錯誤"}), {status:401});
        return new Response(JSON.stringify({message:"登入成功", user}), {status:200});
      }

      // Admin Key 升級驗證
      if (url.pathname === "/api/admin-access" && request.method === "POST") {
        const { username, key } = await request.json();
        const todayStr = new Date().toISOString().slice(0, 10);
        const expectedKey = todayStr + "TGHAdmin";
        
        if (key === expectedKey) {
          await env.DB.prepare("UPDATE users SET role = 'admin' WHERE username = ?").bind(username).run();
          const updatedUser = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(username).first();
          return new Response(JSON.stringify({message:"升級管理員成功", user: updatedUser}), {status:200});
        }
        return new Response(JSON.stringify({error:"Admin Key 錯誤或已過期"}), {status:400});
      }

      // 取得動態牆
      if (url.pathname === "/api/posts" && request.method === "GET") {
        const username = url.searchParams.get("username") || "";
        const { results: posts } = await env.DB.prepare(`
          SELECT p.*, u.avatar_url,
          (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id) as like_count,
          (SELECT COUNT(*) FROM likes l WHERE l.post_id = p.id AND l.username = ?) as is_liked,
          (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) as comment_count
          FROM posts p 
          LEFT JOIN users u ON p.username = u.username 
          WHERE p.is_blocked = 0 ORDER BY p.id DESC
        `).bind(username).all();
        return new Response(JSON.stringify(posts), {headers:{"Content-Type":"application/json"}});
      }

      // 發佈貼文
      if (url.pathname === "/api/posts" && request.method === "POST") {
        const { username, content, image_url, youtube_url } = await request.json();
        if (!username) return new Response(JSON.stringify({error:"請先登入"}), {status:401});
        await env.DB.prepare("INSERT INTO posts (username, content, image_url, youtube_url) VALUES (?, ?, ?, ?)").bind(username, content, image_url || null, youtube_url || null).run();
        return new Response(JSON.stringify({message:"發布成功"}), {status:200});
      }

      // 按讚
      if (url.pathname === "/api/like" && request.method === "POST") {
        const { postId, username } = await request.json();
        const existing = await env.DB.prepare("SELECT * FROM likes WHERE post_id = ? AND username = ?").bind(postId, username).first();
        if (existing) {
          await env.DB.prepare("DELETE FROM likes WHERE post_id = ? AND username = ?").bind(postId, username).run();
          return new Response(JSON.stringify({liked: false}), {status:200});
        } else {
          await env.DB.prepare("INSERT INTO likes (post_id, username) VALUES (?, ?)").bind(postId, username).run();
          return new Response(JSON.stringify({liked: true}), {status:200});
        }
      }

      // 取得留言
      if (url.pathname === "/api/comments" && request.method === "GET") {
        const postId = url.searchParams.get("postId");
        const { results } = await env.DB.prepare("SELECT c.*, u.avatar_url FROM comments c LEFT JOIN users u ON c.username = u.username WHERE c.post_id = ? ORDER BY c.id DESC").bind(postId).all();
        return new Response(JSON.stringify(results), {headers:{"Content-Type":"application/json"}});
      }

      // 新增留言
      if (url.pathname === "/api/comments" && request.method === "POST") {
        const { postId, username, content } = await request.json();
        if (!username || !content) return new Response(JSON.stringify({error:"請輸入內容"}), {status:400});
        await env.DB.prepare("INSERT INTO comments (post_id, username, content) VALUES (?, ?, ?)").bind(postId, username, content).run();
        return new Response(JSON.stringify({message:"留言成功"}), {status:200});
      }

      // 個人資料
      if (url.pathname === "/api/profile" && request.method === "GET") {
        const username = url.searchParams.get("username");
        const user = await env.DB.prepare("SELECT username, role, avatar_url, bio, created_at FROM users WHERE username = ?").bind(username).first();
        const { results: posts } = await env.DB.prepare("SELECT * FROM posts WHERE username = ? AND is_blocked = 0 ORDER BY id DESC").bind(username).all();
        return new Response(JSON.stringify({ user, posts }), {headers:{"Content-Type":"application/json"}});
      }
    }

    // ----------------------------------------------------
    // 【前端 TikTok 風格介面】
    // ----------------------------------------------------
    const html = `<!DOCTYPE html>
<html lang="zh-TW">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>TOGAHO - 影音社群</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,sans-serif;background:#000;color:#fff;overflow:hidden;height:100vh;display:flex;justify-content:center}
.app{width:100%;max-width:480px;height:100vh;background:#121214;position:relative;display:flex;flex-direction:column}
#authModal{position:absolute;inset:0;background:#121214;z-index:100;display:flex;flex-direction:column;justify-content:center;align-items:center;padding:25px}
.auth-box{width:100%;background:#1e1e24;padding:25px;border-radius:16px;box-shadow:0 4px 20px rgba(0,0,0,0.5)}
.auth-title{text-align:center;font-size:22px;font-weight:bold;margin-bottom:20px;color:#ff3b5c}
.admin-section{margin-top:20px;border-top:1px dashed #333;padding-top:15px}
.admin-title{font-size:13px;color:#f39c12;font-weight:bold;margin-bottom:8px}
.top-nav{position:absolute;top:0;left:0;right:0;height:50px;display:flex;justify-content:center;align-items:center;z-index:20;background:linear-gradient(to bottom,rgba(0,0,0,0.7),transparent);font-weight:bold;font-size:16px}
.feed-container{flex:1;overflow-y:scroll;scroll-snap-type:y mandatory;height:100%;scrollbar-width:none}
.feed-container::-webkit-scrollbar{display:none}
.reel-card{width:100%;height:100vh;scroll-snap-align:start;position:relative;background:#000;display:flex;justify-content:center;align-items:center}
.reel-media{width:100%;height:100%;object-fit:cover;position:absolute;top:0;left:0}
.reel-video{width:100%;height:100%;border:none;position:absolute;top:0;left:0}
.reel-overlay{position:absolute;bottom:70px;left:15px;right:80px;z-index:10;text-shadow:0 1px 3px rgba(0,0,0,0.8)}
.reel-author{font-weight:bold;font-size:16px;margin-bottom:6px}
.reel-text{font-size:14px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.action-bar{position:absolute;right:15px;bottom:90px;z-index:10;display:flex;flex-direction:column;align-items:center;gap:18px}
.action-btn{background:none;border:none;color:#fff;display:flex;flex-direction:column;align-items:center;cursor:pointer;font-size:12px}
.action-icon{width:42px;height:42px;background:rgba(255,255,255,0.2);border-radius:50%;display:flex;justify-content:center;align-items:center;font-size:20px;margin-bottom:3px;backdrop-filter:blur(5px)}
.action-icon.liked{color:#ff3b5c;background:rgba(255,59,92,0.2)}
.avatar-badge{width:45px;height:45px;border-radius:50%;border:2px solid #fff;object-fit:cover;margin-bottom:5px}
.bottom-nav{position:absolute;bottom:0;left:0;right:0;height:60px;background:#000;display:flex;justify-content:space-around;align-items:center;z-index:30;border-top:1px solid #222}
.nav-item{background:none;border:none;color:#888;font-size:12px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:2px}
.plus-btn{background:#ff3b5c;color:#fff;width:42px;height:28px;border-radius:8px;font-size:20px;font-weight:bold;display:flex;justify-content:center;align-items:center;border:none;cursor:pointer}
.modal{position:absolute;inset:0;background:rgba(0,0,0,0.8);z-index:50;display:flex;flex-direction:column;justify-content:flex-end;backdrop-filter:blur(5px)}
.modal-content{background:#1e1e24;padding:20px;border-radius:20px 20px 0 0;max-height:80vh;display:flex;flex-direction:column}
input,textarea{width:100%;padding:12px;margin:8px 0;background:#121214;border:1px solid #333;border-radius:8px;color:#fff;font-size:15px}
textarea{height:90px;resize:none}
.btn-primary{background:#ff3b5c;color:#fff;border:none;padding:12px;border-radius:8px;font-weight:bold;cursor:pointer;width:100%;margin-top:10px}
.btn-secondary{background:#333;color:#fff;border:none;padding:10px;border-radius:8px;font-weight:bold;cursor:pointer;width:100%;margin-top:5px;font-size:13px}
.hidden{display:none!important}
</style>
</head>
<body>
<div class="app" id="app">
  <div id="authModal">
    <div class="auth-box">
      <div class="auth-title">TOGAHO 影音社群</div>
      <input type="text" id="authUsername" placeholder="輸入帳號">
      <input type="password" id="authPassword" placeholder="輸入密碼">
      <button class="btn-primary" onclick="handleLogin()">登入</button>
      <button class="btn-secondary" onclick="handleRegister()">註冊新帳號</button>
      <div class="admin-section">
        <div class="admin-title">👑 Admin 管理員專區</div>
        <input type="text" id="adminKeyInput" placeholder="請輸入或取得 Admin Key" style="font-size:13px;">
        <div style="display:flex;gap:8px;">
          <button class="btn-secondary" onclick="requestAdminKey()" style="background:#444;">要求 Key</button>
          <button class="btn-secondary" onclick="verifyAdminKey()" style="background:#f39c12;color:#000;">驗證升級 Admin</button>
        </div>
      </div>
    </div>
  </div>

  <div class="top-nav">推薦</div>
  <div class="feed-container" id="feedContainer"></div>

  <div id="profilePage" class="modal hidden" style="justify-content:center;padding:20px;">
    <div class="modal-content" style="height:80vh;border-radius:16px;">
      <div style="text-align:center;margin-bottom:15px;">
        <img id="profileAvatar" src="" style="width:80px;height:80px;border-radius:50%;object-fit:cover;border:2px solid #ff3b5c;">
        <h3 id="profileUsername" style="margin-top:8px;"></h3>
        <p id="profileRole" style="font-size:12px;color:#f39c12;margin-top:2px;"></p>
        <p id="profileBio" style="font-size:13px;color:#aaa;margin-top:4px;"></p>
        <button onclick="logout()" style="background:#333;color:#ff5555;border:none;padding:6px 15px;border-radius:15px;margin-top:8px;cursor:pointer;font-size:12px;">登出帳號</button>
      </div>
      <h4 style="border-bottom:1px solid #333;padding-bottom:5px;">我的貼文</h4>
      <div id="myPostsList" style="flex:1;overflow-y:auto;margin-top:10px;"></div>
      <button class="btn-primary" onclick="togglePage('profilePage', false)">關閉</button>
    </div>
  </div>

  <div id="commentModal" class="modal hidden">
    <div class="modal-content">
      <h3>留言區</h3>
      <div id="commentList" style="flex:1;overflow-y:auto;max-height:40vh;margin:10px 0;"></div>
      <div style="display:flex;gap:8px;">
        <input type="text" id="commentInput" placeholder="留下你的評論..." style="margin:0;">
        <button onclick="postComment()" style="width:80px;margin:0;background:#ff3b5c;border:none;border-radius:8px;color:#fff;font-weight:bold;">發布</button>
      </div>
      <button onclick="togglePage('commentModal', false)" style="background:none;border:none;color:#888;margin-top:10px;cursor:pointer;">關閉</button>
    </div>
  </div>

  <div id="postModal" class="modal hidden">
    <div class="modal-content">
      <h3>發布新短片 / 貼文</h3>
      <textarea id="postContent" placeholder="寫個精彩的標題或內容..."></textarea>
      <input type="text" id="postImg" placeholder="圖片網址 (選填)">
      <input type="text" id="postYt" placeholder="YouTube Shorts 網址 (選填)">
      <button class="btn-primary" onclick="createPost()">立即發布</button>
      <button onclick="togglePage('postModal', false)" style="background:none;border:none;color:#888;margin-top:10px;cursor:pointer;">取消</button>
    </div>
  </div>

  <div class="bottom-nav">
    <button class="nav-item active">🏠 推薦</button>
    <button class="nav-item" onclick="alert('聊天室功能建置中')">💬 聊天</button>
    <button class="plus-btn" onclick="togglePage('postModal', true)">＋</button>
    <button class="nav-item" onclick="openProfile()">👤 我的</button>
  </div>
</div>

<script>
let currentUser = localStorage.getItem("tgh_user") || null;
let currentRole = localStorage.getItem("tgh_role") || "user";
let currentPostIdForComment = null;

if (currentUser) {
  document.getElementById("authModal").classList.add("hidden");
  loadFeed();
}

async function handleLogin() {
  const username = document.getElementById("authUsername").value;
  const password = document.getElementById("authPassword").value;
  if(!username || !password) return alert("請輸入帳號與密碼");

  let res = await fetch("/api/login", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({username, password})
  });
  if(res.ok) {
    let data = await res.json();
    currentUser = data.user.username;
    currentRole = data.user.role;
    localStorage.setItem("tgh_user", currentUser);
    localStorage.setItem("tgh_role", currentRole);
    document.getElementById("authModal").classList.add("hidden");
    loadFeed();
  } else {
    alert("帳號或密碼錯誤");
  }
}

async function handleRegister() {
  const username = document.getElementById("authUsername").value;
  const password = document.getElementById("authPassword").value;
  if(!username || !password) return alert("請輸入帳號與密碼");

  let res = await fetch("/api/register", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({username, password})
  });
  if(res.ok) {
    alert("註冊成功！已自動為您登入");
    handleLogin();
  } else {
    let err = await res.json();
    alert(err.error || "註冊失敗");
  }
}

function requestAdminKey() {
  const today = new Date().toISOString().slice(0, 10);
  document.getElementById("adminKeyInput").value = today + "TGHAdmin";
  alert("已成功產生今日 Admin Key！");
}

async function verifyAdminKey() {
  const username = document.getElementById("authUsername").value;
  const key = document.getElementById("adminKeyInput").value;
  if(!username) return alert("請先在上方輸入您的帳號名稱");
  if(!key) return alert("請先取得或輸入 Admin Key");

  let res = await fetch("/api/admin-access", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ username, key })
  });
  if(res.ok) {
    let data = await res.json();
    currentUser = data.user.username;
    currentRole = data.user.role;
    localStorage.setItem("tgh_user", currentUser);
    localStorage.setItem("tgh_role", currentRole);
    alert("🎉 恭喜！已成功升級為 Admin 管理員");
    document.getElementById("authModal").classList.add("hidden");
    loadFeed();
  } else {
    let err = await res.json();
    alert(err.error || "Key 驗證失敗");
  }
}

function logout() {
  localStorage.removeItem("tgh_user");
  localStorage.removeItem("tgh_role");
  location.reload();
}

function getYouTubeId(url) {
  if (!url) return "";
  const regExp = /^.*(youtu.be\\/|v\\/|u\\/\\w\\/|embed\\/|watch\\?v=|\\&v=|\\/shorts\\/)([^#\\&\\?]*).*/;
  const match = url.match(regExp);
  return (match && match[2].length === 11) ? match[2] : "";
}

async function loadFeed() {
  const res = await fetch("/api/posts?username=" + encodeURIComponent(currentUser));
  const posts = await res.json();
  const container = document.getElementById("feedContainer");
  container.innerHTML = posts.length === 0 ? "<div style='display:flex;justify-content:center;align-items:center;height:100%;color:#888'>目前沒有短影片貼文，點擊下方 [+] 發布第一則吧！</div>" : "";

  posts.forEach(p => {
    let mediaContent = "";
    if (p.youtube_url) {
      const ytId = getYouTubeId(p.youtube_url);
      if (ytId) mediaContent = '<iframe class="reel-video" src="https://www.youtube.com/embed/' + ytId + '?autoplay=1&mute=1&loop=1" allow="autoplay"></iframe>';
    } else if (p.image_url) {
      mediaContent = '<img class="reel-media" src="' + p.image_url + '">';
    } else {
      mediaContent = '<div class="reel-media" style="background:#202028;display:flex;align-items:center;justify-content:center;padding:30px;text-align:center;">' + p.content + '</div>';
    }

    const likedClass = p.is_liked > 0 ? "liked" : "";

    container.innerHTML += '<div class="reel-card">' + mediaContent + '<div class="reel-overlay"><div class="reel-author">@' + p.username + '</div><div class="reel-text">' + p.content + '</div></div><div class="action-bar"><img class="avatar-badge" src="' + (p.avatar_url || 'https://picsum.photos/200') + '"><button class="action-btn" onclick="toggleLike(' + p.id + ')"><div class="action-icon ' + likedClass + '">♥</div><span>' + p.like_count + '</span></button><button class="action-btn" onclick="openComments(' + p.id + ')"><div class="action-icon">💬</div><span>' + p.comment_count + '</span></button></div></div>';
  });
}

async function toggleLike(postId) {
  await fetch("/api/like", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ postId, username: currentUser })
  });
  loadFeed();
}

async function openComments(postId) {
  currentPostIdForComment = postId;
  togglePage('commentModal', true);
  const res = await fetch("/api/comments?postId=" + postId);
  const comments = await res.json();
  const list = document.getElementById("commentList");
  list.innerHTML = comments.length === 0 ? "<p style='color:#777;text-align:center;'>還沒有人留言，搶頭香吧！</p>" : "";
  comments.forEach(c => {
    list.innerHTML += '<div style="margin-bottom:10px;font-size:13px;"><b style="color:#ff3b5c">@' + c.username + ':</b> ' + c.content + '</div>';
  });
}

async function postComment() {
  const content = document.getElementById("commentInput").value;
  if (!content) return;
  await fetch("/api/comments", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ postId: currentPostIdForComment, username: currentUser, content })
  });
  document.getElementById("commentInput").value = "";
  openComments(currentPostIdForComment);
  loadFeed();
}

async function createPost() {
  const content = document.getElementById("postContent").value;
  const image_url = document.getElementById("postImg").value;
  const youtube_url = document.getElementById("postYt").value;
  const res = await fetch("/api/posts", {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify({ username: currentUser, content, image_url, youtube_url })
  });
  if (res.ok) {
    togglePage('postModal', false);
    document.getElementById("postContent").value = "";
    document.getElementById("postImg").value = "";
    document.getElementById("postYt").value = "";
    loadFeed();
  }
}

async function openProfile() {
  togglePage('profilePage', true);
  const res = await fetch("/api/profile?username=" + encodeURIComponent(currentUser));
  const data = await res.json();
  document.getElementById("profileAvatar").src = data.user.avatar_url || 'https://picsum.photos/200';
  document.getElementById("profileUsername").innerText = "@" + data.user.username;
  document.getElementById("profileRole").innerText = "身分：" + (data.user.role === 'admin' ? '👑 系統管理員 (Admin)' : '一般會員');
  document.getElementById("profileBio").innerText = data.user.bio || "尚無簡介";
  
  const myPosts = document.getElementById("myPostsList");
  myPosts.innerHTML = "";
  data.posts.forEach(p => {
    myPosts.innerHTML += '<div style="background:#121214;padding:10px;margin-bottom:8px;border-radius:8px;font-size:13px;">' + p.content + '</div>';
  });
}

function togglePage(pageId, show) {
  const el = document.getElementById(pageId);
  if (show) el.classList.remove("hidden");
  else el.classList.add("hidden");
}
</script>
</body>
</html>`;

    return new Response(html, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
  }
};
