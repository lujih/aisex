/**
 * 秘密花园 (Secret Garden) - v6.0
 * 功能: 编辑+改密+时区+无限流+图表交互
 * 数据库: Cloudflare D1 (绑定变量: DB)
 */

const DEFAULT_JWT_SECRET = 'change-this-secret-in-env-vars-please'; 
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// --- 翻译映射表 (保持原样) ---
const TR_MAP = {
  'bedroom': '卧室', 'living_room': '客厅', 'bathroom': '浴室', 'hotel': '酒店', 'car': '车内', 'outdoor': '野战', 'office': '办公室', 'public_space': '公共场所', 'pool': '泳池', 'friend_house': '朋友家', 'other': '其他',
  'horny': '🔥 性致勃勃', 'romantic': '🌹 浪漫', 'passionate': '❤️‍🔥 激情', 'aggressive': '😈 暴躁/发泄', 'stressed': '😫 压力释放', 'lazy': '🛌 慵懒', 'bored': '🥱 无聊', 'happy': '🥰 开心', 'drunk': '🍷 微醺', 'high': '🌿 嗨大了', 'experimental': '🧪 猎奇', 'morning_wood': '🌅 晨勃', 'lonely': '🌑 孤独', 'sad': '😢 悲伤', 'none': '纯想象', 'fantasy': '特定幻想', 
  'porn_pov': 'AV-POV', 'porn_amateur': 'AV-素人', 'porn_pro': 'AV-片商', 'hentai': '二次元', 'erotica': '黄文', 'audio': '娇喘/ASMR', 'hypno': '催眠', 'cam': '网聊', 'photos': '套图', 'ntr': 'NTR', 'femdom': '女S',
  'm_hand': '传统手冲', 'm_prone': '俯卧(日地)', 'm_edging': '边缘控射', 'm_death_grip': '死握', 'm_slow': '慢玩', 'm_prostate': '前列腺', 'm_anal_play': '后庭把玩', 'm_docking': '夹腿',
  'toy_cup': '飞机杯', 'toy_vibe': '震动棒', 'toy_anal': '肛塞', 'toy_milker': '榨精机', 'toy_doll': '娃娃', 'toy_lube': '大量润滑',
  'kissing': '接吻', 'cuddling': '爱抚', 'massage': '按摩', 'dirty_talk': '脏话', 'oral_give': '口(攻)', 'oral_receive': '口(受)', '69': '69式', 'rimming': '舔肛', 'nipple_play': '乳头刺激', 'spanking': 'SP/打屁股', 'bondage': '束缚', 'fingering': '指交', 'manual': '手交', 'vaginal': '阴道', 'anal': '后庭', 'facial': '颜射', 'creampie': '内射', 'swallowing': '吞精',
  'missionary': '传教士', 'doggy': '后入', 'cowgirl': '女上位', 'reverse_cowgirl': '反向女上', 'spoons': '勺子式', 'standing': '站立', 'prone_bone': '俯卧后入', 'legs_up': '架腿'
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    try {
      if (path === '/' || path === '/index.html') return serveFrontend();
      
      // 公开路由
      if (path === '/api/auth/register') return await registerUser(request, env);
      if (path === '/api/auth/login') return await loginUser(request, env);

      // 鉴权
      const user = await verifyAuth(request, env);
      if (!user) return errorResponse('Unauthorized', 401);

      // 业务路由
      if (path === '/api/auth/password') return await changePassword(request, env, user); // 修改密码
      
      if (path === '/api/records') {
        if (request.method === 'GET') return await getRecords(request, env, user);
        if (request.method === 'POST') return await createRecord(request, env, user);
        if (request.method === 'PUT') return await updateRecord(request, env, user);
        if (request.method === 'DELETE') return await deleteRecord(url, env, user);
      } 
      else if (path === '/api/records/detail') return await getRecordDetail(url, env, user); // 获取单条详情
      else if (path === '/api/statistics') return await getStatistics(url, env, user); // 统计(带筛选)
      else if (path === '/api/leaderboard') return await getLeaderboard(env);
      
      return new Response('Not found', { status: 404, headers: CORS_HEADERS });
    } catch (error) {
      return errorResponse(error.message, 500);
    }
  }
};

// ==========================================
// 业务逻辑
// ==========================================

async function getRecords(req, env, user) {
  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20; // 配合无限滚动
  const offset = (page - 1) * limit;
  const search = (url.searchParams.get('search') || '').trim();

  let sql = `SELECT * FROM records WHERE uid = ?`;
  let params = [user.uid];

  if (search) {
    sql += ` AND (data_json LIKE ? OR location LIKE ? OR mood LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  sql += ` ORDER BY datetime DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const { results } = await env.DB.prepare(sql).bind(...params).all();
  
  // 展开 JSON
  const records = results.map(r => {
    let extra = {};
    try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    return { ...r, ...extra, data_json: undefined };
  });

  return jsonResponse({ records, page });
}

// 获取单条详情 (用于编辑回显)
async function getRecordDetail(url, env, user) {
    const id = url.searchParams.get('id');
    const r = await env.DB.prepare('SELECT * FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).first();
    if (!r) return errorResponse('记录不存在', 404);
    
    let extra = {};
    try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    return jsonResponse({ ...r, ...extra, data_json: undefined });
}

async function createRecord(req, env, user) {
  const data = await req.json();
  const id = generateId();
  const { core, extra } = splitData(data, user.uid, id);

  await env.DB.prepare(`
    INSERT INTO records (
      id, uid, activity_type, datetime, duration, location, mood, 
      satisfaction, orgasm_count, ejaculation_count, data_json, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    core.id, core.uid, core.activity_type, core.datetime, core.duration, core.location, core.mood,
    core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra), new Date().toISOString()
  ).run();

  return jsonResponse({ message: '创建成功', id });
}

async function updateRecord(req, env, user) {
  const data = await req.json();
  if (!data.id) return errorResponse('缺少ID');
  
  const existing = await env.DB.prepare('SELECT id FROM records WHERE id = ? AND uid = ?').bind(data.id, user.uid).first();
  if (!existing) return errorResponse('无权修改', 403);

  const { core, extra } = splitData(data, user.uid, data.id);

  await env.DB.prepare(`
    UPDATE records SET 
      activity_type = ?, datetime = ?, duration = ?, location = ?, mood = ?, 
      satisfaction = ?, orgasm_count = ?, ejaculation_count = ?, data_json = ?
    WHERE id = ? AND uid = ?
  `).bind(
    core.activity_type, core.datetime, core.duration, core.location, core.mood,
    core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra),
    core.id, core.uid
  ).run();

  return jsonResponse({ message: '更新成功' });
}

async function deleteRecord(url, env, user) {
  const id = url.searchParams.get('id');
  await env.DB.prepare('DELETE FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).run();
  return jsonResponse({ message: '删除成功' });
}

async function getStatistics(url, env, user) {
  const range = url.searchParams.get('range') || 'all';
  let timeFilter = '';
  
  // D1 (SQLite) 时间筛选
  if (range === 'month') timeFilter = " AND datetime >= datetime('now', 'start of month')";
  else if (range === 'year') timeFilter = " AND datetime >= datetime('now', '-1 year')";
  else if (range === '3_months') timeFilter = " AND datetime >= datetime('now', '-3 months')";

  const sql = `
    SELECT 
      count(*) as total_records,
      sum(case when activity_type = 'masturbation' then 1 else 0 end) as masturbation,
      sum(case when activity_type = 'intercourse' then 1 else 0 end) as intercourse,
      sum(orgasm_count) as total_orgasms,
      avg(satisfaction) as avg_satisfaction,
      avg(duration) as avg_duration
    FROM records WHERE uid = ? ${timeFilter}
  `;
  
  const stats = await env.DB.prepare(sql).bind(user.uid).first();

  // 图表数据也根据时间范围变化
  const monthSql = `
    SELECT strftime('%Y-%m', datetime) as month, count(*) as count 
    FROM records WHERE uid = ? ${timeFilter}
    GROUP BY month 
    ORDER BY month DESC LIMIT 12
  `;
  const monthRes = await env.DB.prepare(monthSql).bind(user.uid).all();
  
  const records_by_month = {};
  if(monthRes.results) [...monthRes.results].reverse().forEach(row => records_by_month[row.month] = row.count);

  return jsonResponse({
    total_records: stats.total_records || 0,
    masturbation: stats.masturbation || 0,
    intercourse: stats.intercourse || 0,
    total_orgasms: stats.total_orgasms || 0,
    avg_satisfaction: parseFloat((stats.avg_satisfaction || 0).toFixed(1)),
    avg_duration: Math.round(stats.avg_duration || 0),
    records_by_month
  });
}

async function getLeaderboard(env) {
    // 排行榜展示全量数据
    const { results } = await env.DB.prepare(`
      SELECT u.username, count(r.id) as total_records, sum(r.duration) as total_duration,
      sum(case when r.activity_type = 'masturbation' then 1 else 0 end) as masturbation_count
      FROM records r JOIN users u ON r.uid = u.uid
      GROUP BY u.uid ORDER BY total_duration DESC LIMIT 50
    `).all();
    return jsonResponse(results);
}

// ==========================================
// 认证与密码管理
// ==========================================

async function registerUser(req, env) {
  const { username, password } = await req.json();
  if (!username || !password || username.length < 3) return errorResponse('无效参数');
  try {
    const uid = generateId();
    await env.DB.prepare('INSERT INTO users (uid, username, password_hash) VALUES (?, ?, ?)')
      .bind(uid, username, await hashPassword(password)).run();
    return jsonResponse({ message: '注册成功' });
  } catch (e) { return errorResponse('用户名已存在'); }
}

async function loginUser(req, env) {
  const { username, password } = await req.json();
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || (await hashPassword(password)) !== user.password_hash) return errorResponse('用户或密码错误', 401);
  const token = await signJwt({ uid: user.uid, username: user.username }, env.JWT_SECRET || DEFAULT_JWT_SECRET);
  return jsonResponse({ token, username });
}

async function changePassword(req, env, user) {
  const { oldPassword, newPassword } = await req.json();
  if(!newPassword || newPassword.length < 5) return errorResponse('新密码太短');
  
  const dbUser = await env.DB.prepare('SELECT password_hash FROM users WHERE uid = ?').bind(user.uid).first();
  if((await hashPassword(oldPassword)) !== dbUser.password_hash) return errorResponse('旧密码错误', 403);
  
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE uid = ?')
    .bind(await hashPassword(newPassword), user.uid).run();
  
  return jsonResponse({ message: '修改成功' });
}

// ==========================================
// 工具函数
// ==========================================

function splitData(data, uid, id) {
    const coreMap = ['activity_type','datetime','duration','location','mood','satisfaction','orgasm_count','ejaculation_count'];
    const core = { uid, id, duration:0, satisfaction:0, orgasm_count:0, ejaculation_count:0 };
    const extra = {};
    for (let k in data) {
        if (coreMap.includes(k)) core[k] = data[k];
        else if (k !== 'id' && k !== 'uid' && k !== 'created_at') extra[k] = data[k];
    }
    // 确保数字类型
    ['duration','satisfaction','orgasm_count','ejaculation_count'].forEach(k => core[k] = parseInt(core[k]) || 0);
    return { core, extra };
}

async function hashPassword(pw) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyAuth(request, env) {
  const h = request.headers.get('Authorization');
  if (!h || !h.startsWith('Bearer ')) return null;
  try { return await verifyJwt(h.split(' ')[1], env.JWT_SECRET || DEFAULT_JWT_SECRET); } catch (e) { return null; }
}

async function signJwt(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+604800 }));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}
async function verifyJwt(token, secret) {
  const [h, b, s] = token.split('.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  if (!await crypto.subtle.verify('HMAC', key, b64urlDecode(s), new TextEncoder().encode(`${h}.${b}`))) throw new Error('Invalid');
  const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(b)));
  if (payload.exp < Date.now()/1000) throw new Error('Expired');
  return payload;
}
function b64url(s) { return (typeof s==='string'?btoa(s):btoa(String.fromCharCode(...new Uint8Array(s)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(s) { return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }
function jsonResponse(data, status = 200) { return new Response(JSON.stringify(data), { status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }); }
function errorResponse(msg, status = 400) { return jsonResponse({ error: msg }, status); }
function generateId() { return Date.now().toString(36) + Math.random().toString(36).substring(2, 6); }

// ==========================================
// 前端 HTML
// ==========================================
async function serveFrontend() {
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <title>秘密花园 - 极乐统计</title>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;700&family=Playfair+Display:wght@700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.min.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root { --primary: #ff0055; --primary-glow: rgba(255, 0, 85, 0.6); --secondary: #bc13fe; --glass-bg: rgba(30, 30, 40, 0.45); --glass-border: rgba(255, 255, 255, 0.12); --glass-blur: blur(20px); --text-main: #f0f0f0; }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body { background-color: #0f0c15; color: var(--text-main); font-family: 'Noto Sans SC', sans-serif; margin: 0; padding-bottom: 110px; min-height: 100vh; overflow-x: hidden; }
    #bg-carousel { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; pointer-events: none; }
    .bg-slide { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-size: cover; background-position: center; opacity: 0; transition: opacity 3s ease-in-out; transform: scale(1.1); }
    .bg-slide.active { opacity: 1; }
    .bg-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; background: radial-gradient(circle at center, rgba(15,12,21,0.5) 0%, rgba(15,12,21,0.95) 100%); }
    h1, h2 { font-family: 'Playfair Display', serif; color: #fff; letter-spacing: 1px; }
    .container { max-width: 900px; margin: 0 auto; padding: 20px 15px; }
    .glass { background: var(--glass-bg); backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur); border: 1px solid var(--glass-border); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
    .glass-panel { border-radius: 16px; padding: 15px; margin-bottom: 20px; }
    .button { background: linear-gradient(135deg, rgba(255,0,85,0.8), rgba(188,19,254,0.8)); border: 0; border-radius: 50px; font-weight: 700; height: 3.6rem; line-height: 3.6rem; padding: 0 20px; color: #fff; text-transform: none; box-shadow: 0 4px 15px var(--primary-glow); }
    .button-outline { background: rgba(255,255,255,0.05); border: 1px solid var(--primary); color: var(--primary); box-shadow: none; }
    .button-small { height: 2.8rem; line-height: 2.6rem; padding: 0 12px; font-size: 0.85rem; }
    .button-group { display: flex; gap: 8px; overflow-x: auto; padding-bottom: 5px; }
    input, select, textarea { background-color: rgba(0, 0, 0, 0.3) !important; border: 1px solid rgba(255,255,255,0.15) !important; color: #fff !important; border-radius: 12px !important; }
    #loginModal, #pwdModal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2000; background: rgba(15,12,21,0.9); display: flex; align-items: center; justify-content: center; }
    .login-box { width: 90%; max-width: 400px; padding: 30px; text-align: center; }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
    .stat-item { text-align: center; padding: 10px; border-radius: 12px; background: rgba(255,255,255,0.03); }
    .stat-num { font-size: 1.4rem; color: var(--primary); display: block; font-family: 'Playfair Display'; }
    .record-item { border-radius: 12px; margin-bottom: 12px; padding: 15px; border-left: 4px solid #555; position: relative; }
    .type-m { border-left-color: var(--secondary); background: linear-gradient(90deg, rgba(188,19,254,0.1), rgba(0,0,0,0)); }
    .type-i { border-left-color: var(--primary); background: linear-gradient(90deg, rgba(255,0,85,0.1), rgba(0,0,0,0)); }
    .tags-row { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 8px; }
    .tag { font-size: 0.75rem; padding: 2px 8px; border-radius: 8px; background: rgba(255,255,255,0.1); color: #ddd; }
    #modalOverlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 1000; background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); display: none; justify-content: center; align-items: flex-start; overflow-y: auto; padding: 20px 10px 100px; }
    #modalContent { width: 100%; max-width: 650px; padding: 20px; margin-top: 20px; color: #eee; }
    .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(85px, 1fr)); gap: 8px; margin-bottom: 10px; }
    .cb-btn input { display: none; }
    .cb-btn label { display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.05); color: #aaa; padding: 0 4px; height: 38px; border-radius: 10px; cursor: pointer; font-size: 0.8rem; border: 1px solid rgba(255,255,255,0.1); transition: 0.2s; }
    .cb-btn input:checked + label { background: var(--primary); color: #fff; border-color: var(--primary); }
    .hidden { display: none !important; }
    #timer-bar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); width: 90%; max-width: 600px; z-index: 99; border-radius: 50px; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
    .loader { text-align: center; padding: 20px; color: #666; font-size: 0.9rem; }
  </style>
</head>
<body>
  <div id="bg-carousel"></div><div class="bg-overlay"></div>

  <!-- 登录框 -->
  <div id="loginModal">
    <div class="login-box glass">
      <h2 style="margin-bottom:30px;">Secret Garden</h2>
      <input type="text" id="lg-user" placeholder="用户名" style="margin-bottom:15px;">
      <input type="password" id="lg-pass" placeholder="密码" style="margin-bottom:25px;">
      <button class="button" style="width:100%; margin-bottom:15px;" onclick="doLogin()">登 录</button>
      <button class="button button-outline" style="width:100%;" onclick="doRegister()">注 册</button>
      <div id="loginMsg" style="margin-top:15px; color: var(--primary);"></div>
    </div>
  </div>

  <!-- 修改密码框 -->
  <div id="pwdModal" class="hidden">
    <div class="login-box glass">
      <h3>修改密码</h3>
      <input type="password" id="pwd-old" placeholder="旧密码" style="margin-bottom:15px;">
      <input type="password" id="pwd-new" placeholder="新密码" style="margin-bottom:25px;">
      <button class="button" style="width:100%; margin-bottom:15px;" onclick="changePassword()">确 认</button>
      <button class="button button-outline" style="width:100%;" onclick="document.getElementById('pwdModal').classList.add('hidden')">取 消</button>
    </div>
  </div>

  <div class="container" id="app" style="filter: blur(10px);">
    <header style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
      <h1>秘密花园</h1>
      <div>
        <span id="welcomeUser" style="font-size:0.9rem; margin-right:5px; color:#ccc;"></span>
        <a href="#" style="font-size:0.8rem; color:var(--primary); margin-right:10px;" onclick="document.getElementById('pwdModal').classList.remove('hidden')">改密</a>
        <button class="button button-small button-outline" onclick="logout()">退出</button>
      </div>
    </header>

    <div class="button-group" style="margin-bottom:15px;">
      <button class="button button-small" onclick="switchView('home')">🏠 统计</button>
      <button class="button button-small button-outline" onclick="switchView('leaderboard')">🏆 榜单</button>
      <button class="button button-small button-outline" onclick="openModal(false)">+ 补录</button>
    </div>

    <!-- 主页 -->
    <div id="view-home">
        <!-- 统计筛选 -->
        <div style="display:flex; justify-content:flex-end; gap:5px; margin-bottom:10px;">
           <button class="button button-small button-outline" onclick="loadStats('month')">本月</button>
           <button class="button button-small button-outline" onclick="loadStats('3_months')">近3月</button>
           <button class="button button-small button-outline" onclick="loadStats('year')">今年</button>
           <button class="button button-small button-outline" onclick="loadStats('all')">全部</button>
        </div>

        <div class="stats-grid glass">
            <div class="stat-item"><span class="stat-num" id="sTotal">0</span>总次数</div>
            <div class="stat-item"><span class="stat-num" id="sDuration">0</span>均时长</div>
            <div class="stat-item"><span class="stat-num" id="sScore">0</span>满意度</div>
            <div class="stat-item"><span class="stat-num" id="sOrgasm">0</span>总高潮</div>
        </div>

        <div class="glass glass-panel" style="display: flex; flex-wrap: wrap; gap: 15px; justify-content: space-around;">
            <div style="flex: 1; min-width: 250px; height: 200px;"><canvas id="chartHistory"></canvas></div>
            <div style="flex: 1; min-width: 200px; height: 200px; max-width: 300px;"><canvas id="chartType"></canvas></div>
        </div>

        <div style="display:flex; gap:10px; margin-bottom:15px;">
           <input type="text" id="searchInput" placeholder="🔍 搜索玩法、备注..." style="height:3.6rem;">
           <button class="button button-small" onclick="resetList(); loadRecords()">搜索</button>
        </div>

        <div id="listContainer"></div>
        <div id="scrollSentinel" class="loader">正在加载更多...</div>
    </div>

    <!-- 榜单 -->
    <div id="view-leaderboard" class="hidden">
        <div class="glass glass-panel">
            <h3 style="border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:10px;">🏆 极乐榜 (Top 50)</h3>
            <table style="width:100%; color:#fff;">
                <thead><tr><th>#</th><th>玩家</th><th>时长</th><th>次数</th></tr></thead>
                <tbody id="leaderboardBody"></tbody>
            </table>
        </div>
    </div>
  </div>

  <!-- 计时器 -->
  <div id="timer-bar" class="glass">
      <div id="timer-info" style="display:none; flex-direction:column;"><span style="font-size:0.7rem; color:#aaa;">SESSION TIME</span><span id="globalTimerDisplay" style="font-family:monospace; font-size:1.4rem; font-weight:bold; color:#fff;">00:00:00</span></div>
      <div id="timer-idle" style="font-size:1.1rem; color:#ddd; font-weight:bold;">准备好了吗?</div>
      <button id="btnGlobalTimer" class="button button-small" style="height:3.5rem; border-radius:30px;" onclick="toggleGlobalTimer()">⏱️ 开始</button>
  </div>

  <!-- 记录详情/编辑弹窗 -->
  <div id="modalOverlay">
    <div id="modalContent" class="glass glass-panel">
      <h3 id="formTitle" style="margin:0 0 10px; border-bottom:1px solid #555;">详情</h3>
      <input type="hidden" id="recordId">
      
      <div style="display:flex; gap:10px;">
        <div style="flex:1"><label>类型</label><select id="activityType"><option value="masturbation">🖐 自慰</option><option value="intercourse">❤️ 性爱</option></select></div>
        <div style="flex:1"><label>时间 (本地)</label><input type="datetime-local" id="datetime"></div>
      </div>
      
      <div style="display:flex; gap:10px;">
        <div style="flex:1"><label>地点</label><select id="location"><option value="bedroom">卧室</option><option value="living_room">客厅</option><option value="bathroom">浴室</option><option value="hotel">酒店</option><option value="car">车内</option><option value="outdoor">野战</option><option value="office">办公室</option><option value="other">其他</option></select></div>
        <div style="flex:1"><label>心情</label><select id="mood"><option value="horny">🔥 性致勃勃</option><option value="lonely">🌑 孤独</option><option value="stressed">😫 压力</option><option value="bored">🥱 无聊</option><option value="drunk">🍷 微醺</option><option value="morning_wood">🌅 晨勃</option></select></div>
      </div>

      <div id="sectionMasturbation">
        <label>助兴</label><select id="stimulation"><option value="none">无</option><option value="porn_pov">POV</option><option value="porn_amateur">素人</option><option value="hentai">二次元</option><option value="erotica">黄文</option><option value="fantasy">幻想</option></select>
        <label>玩法</label>
        <div class="checkbox-grid">
           <div class="cb-btn"><input type="checkbox" name="acts" id="m_hand" value="m_hand"><label for="m_hand">手冲</label></div>
           <div class="cb-btn"><input type="checkbox" name="acts" id="m_edging" value="m_edging"><label for="m_edging">控射</label></div>
           <div class="cb-btn"><input type="checkbox" name="acts" id="m_prostate" value="m_prostate"><label for="m_prostate">前列腺</label></div>
           <div class="cb-btn"><input type="checkbox" name="acts" id="toy_cup" value="toy_cup"><label for="toy_cup">飞机杯</label></div>
        </div>
      </div>

      <div id="sectionIntercourse" class="hidden">
        <div style="display:flex; gap:10px;"><div style="flex:1"><label>伴侣</label><input type="text" id="partnerName"></div></div>
        <label>体位</label><select id="sexualPosition"><option value="">--</option><option value="missionary">传教士</option><option value="doggy">后入</option><option value="cowgirl">女上</option></select>
        <label>行为</label>
        <div class="checkbox-grid">
           <div class="cb-btn"><input type="checkbox" name="acts" id="act_oral" value="oral_give"><label for="act_oral">口(攻)</label></div>
           <div class="cb-btn"><input type="checkbox" name="acts" id="act_vag" value="vaginal"><label for="act_vag">阴道</label></div>
           <div class="cb-btn"><input type="checkbox" name="acts" id="act_creampie" value="creampie"><label for="act_creampie">内射</label></div>
        </div>
      </div>

      <div style="margin-top:15px; border-top:1px solid #555; padding-top:10px;">
        <div style="display:flex; gap:10px;">
           <div style="flex:1"><label>时长: <span id="vDur" style="color:var(--primary)">15</span>分</label><input type="range" id="duration" min="0" max="120" value="15" oninput="document.getElementById('vDur').innerText=this.value"></div>
           <div style="flex:1"><label>满意: <span id="vSat" style="color:var(--primary)">5</span></label><input type="range" id="satisfaction" min="1" max="10" value="5" oninput="document.getElementById('vSat').innerText=this.value"></div>
        </div>
        <div style="display:flex; gap:10px;">
           <div style="flex:1"><label>高潮</label><input type="number" id="orgasmCount" value="1"></div>
           <div style="flex:1"><label>射精</label><input type="number" id="ejaculationCount" value="1"></div>
        </div>
      </div>

      <textarea id="experience" placeholder="详细体验..." style="min-height:80px; margin-top:10px;"></textarea>
      
      <div style="display:flex; gap:10px; margin-top:20px;">
        <button class="button button-outline" style="flex:1" onclick="document.getElementById('modalOverlay').style.display='none'">取消</button>
        <button class="button" style="flex:2" onclick="saveRecord()">保存</button>
      </div>
    </div>
  </div>

  <script>
    const API = '/api';
    const TR_MAP = ${JSON.stringify(TR_MAP)};
    function tr(k) { return TR_MAP[k] || k; }
    
    let token = localStorage.getItem('sg_token');
    let user = localStorage.getItem('sg_user');
    let currentPage = 1, isLoading = false, hasMore = true;
    let chart1, chart2, timerInterval;

    // 初始化
    (function() {
      initBackground(); initTimerState();
      if(token) {
        document.getElementById('loginModal').style.display='none';
        document.getElementById('app').style.filter='none';
        document.getElementById('welcomeUser').innerText = user;
        loadStats();
        setupInfiniteScroll();
      }
      document.getElementById('activityType').addEventListener('change', e => {
         const isM = e.target.value === 'masturbation';
         document.getElementById('sectionMasturbation').classList.toggle('hidden', !isM);
         document.getElementById('sectionIntercourse').classList.toggle('hidden', isM);
      });
    })();

    function getHeaders() { return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }; }

    // --- 认证 ---
    async function doLogin() {
        authAction('/auth/login');
    }
    async function doRegister() {
        authAction('/auth/register');
    }
    async function authAction(endpoint) {
        try {
            const u = document.getElementById('lg-user').value;
            const p = document.getElementById('lg-pass').value;
            const r = await fetch(API+endpoint, { method:'POST', body:JSON.stringify({username:u, password:p}) });
            const d = await r.json();
            if(d.error) throw new Error(d.error);
            if(d.token) {
                localStorage.setItem('sg_token', d.token); localStorage.setItem('sg_user', d.username);
                location.reload();
            } else { alert(d.message); }
        } catch(e){ document.getElementById('loginMsg').innerText=e.message; }
    }
    async function changePassword() {
        try {
            const oldP = document.getElementById('pwd-old').value;
            const newP = document.getElementById('pwd-new').value;
            const r = await fetch(API+'/auth/password', { method:'POST', headers:getHeaders(), body:JSON.stringify({oldPassword:oldP, newPassword:newP}) });
            const d = await r.json();
            if(d.error) alert(d.error);
            else { alert('修改成功'); document.getElementById('pwdModal').classList.add('hidden'); }
        } catch(e){ alert('错误'); }
    }
    function logout() { localStorage.clear(); location.reload(); }

    // --- 数据加载 ---
    async function loadStats(range='all') {
        try {
            const r = await fetch(API+'/statistics?range='+range, { headers: getHeaders() });
            const s = await r.json();
            if(s.error === 'Unauthorized') return logout();
            
            document.getElementById('sTotal').innerText = s.total_records;
            document.getElementById('sDuration').innerText = s.avg_duration;
            document.getElementById('sScore').innerText = s.avg_satisfaction;
            document.getElementById('sOrgasm').innerText = s.total_orgasms;
            
            // 图表更新
            if(chart1) chart1.destroy();
            chart1=new Chart(document.getElementById('chartType'),{type:'doughnut',data:{labels:['自慰','性爱'],datasets:[{data:[s.masturbation,s.intercourse],backgroundColor:['#bc13fe','#ff0055'],borderWidth:0}]},options:{maintainAspectRatio:false,plugins:{legend:{position:'bottom'}}}});
            
            if(chart2) chart2.destroy();
            const m=Object.keys(s.records_by_month).sort(); // 后端已排序，这里确保顺序
            chart2=new Chart(document.getElementById('chartHistory'),{type:'bar',data:{labels:m,datasets:[{label:'次数',data:m.map(k=>s.records_by_month[k]),backgroundColor:'#ff0055',borderRadius:4}]},options:{maintainAspectRatio:false,scales:{x:{grid:{display:false}},y:{grid:{color:'rgba(255,255,255,0.05)'}}},plugins:{legend:{display:false}}}});
        } catch(e){}
    }

    function resetList() { currentPage=1; hasMore=true; document.getElementById('listContainer').innerHTML=''; }
    
    async function loadRecords() {
        if(isLoading || !hasMore) return;
        isLoading = true;
        document.getElementById('scrollSentinel').innerText = '加载中...';
        
        const q = document.getElementById('searchInput').value;
        try {
            const r = await fetch(\`\${API}/records?page=\${currentPage}&search=\${q}\`, { headers: getHeaders() });
            const d = await r.json();
            if(d.records.length === 0) {
                hasMore = false;
                document.getElementById('scrollSentinel').innerText = '没有更多了';
            } else {
                renderList(d.records);
                currentPage++;
                document.getElementById('scrollSentinel').innerText = '下滑加载更多';
            }
        } catch(e) { hasMore=false; }
        isLoading = false;
    }

    function renderList(list) {
        const c = document.getElementById('listContainer');
        list.forEach(item => {
            const isM = item.activity_type === 'masturbation';
            // UTC 转 本地时间显示
            const d = new Date(item.datetime);
            const dateStr = d.toLocaleString('zh-CN', {month:'numeric', day:'numeric', hour:'2-digit', minute:'2-digit'});
            
            let tags = item.location ? \`<span class="tag">\${tr(item.location)}</span>\` : '';
            if(item.stimulation && item.stimulation!=='none') tags+=\`<span class="tag">\${tr(item.stimulation)}</span>\`;
            if(item.acts) {
                try {
                    const acts = typeof item.acts === 'string' ? JSON.parse(item.acts) : item.acts;
                    acts.slice(0,3).forEach(a => tags+=\`<span class="tag">\${tr(a)}</span>\`);
                } catch(e){}
            }

            const html = \`
               <div class="glass record-item \${isM?'type-m':'type-i'}" onclick="editRecord('\${item.id}')">
                  <div style="display:flex;justify-content:space-between;color:#fff;font-weight:bold;margin-bottom:5px;">
                     <span>\${isM?'🖐 自慰':'❤️ 性爱'}</span>
                     <div style="font-size:0.8rem;color:#aaa;">\${item.duration}分 · \${item.satisfaction}分</div>
                  </div>
                  <div style="font-size:0.8rem;color:#ccc;margin-bottom:6px;">\${dateStr}</div>
                  <div class="tags-row">\${tags}</div>
               </div>\`;
            c.insertAdjacentHTML('beforeend', html);
        });
    }

    // --- 编辑与表单 ---
    async function editRecord(id) {
        try {
            const r = await fetch(API+'/records/detail?id='+id, { headers: getHeaders() });
            const d = await r.json();
            if(d.error) return alert(d.error);
            
            openModal(true);
            document.getElementById('recordId').value = d.id;
            document.getElementById('activityType').value = d.activity_type;
            
            // 时区转换: UTC ISO -> Local datetime-local value (YYYY-MM-DDTHH:mm)
            const utcDate = new Date(d.datetime);
            const localDate = new Date(utcDate.getTime() - (utcDate.getTimezoneOffset() * 60000));
            document.getElementById('datetime').value = localDate.toISOString().slice(0,16);

            ['location','mood','stimulation','partnerName','sexualPosition','experience'].forEach(k => {
                if(document.getElementById(k)) document.getElementById(k).value = d[k]||'';
            });
            ['duration','satisfaction','orgasmCount','ejaculationCount'].forEach(k => {
                document.getElementById(k).value = d[k]||0;
            });
            document.getElementById('valDuration').innerText = d.duration;
            document.getElementById('valScore').innerText = d.satisfaction;

            // 复选框回显
            const acts = d.acts || [];
            document.querySelectorAll('input[name="acts"]').forEach(cb => {
                cb.checked = acts.includes(cb.value);
            });
            document.getElementById('activityType').dispatchEvent(new Event('change'));
            
        } catch(e) { alert('加载失败'); }
    }

    function openModal(isEdit, duration) {
        document.getElementById('modalOverlay').style.display = 'flex';
        document.getElementById('formTitle').innerText = isEdit ? '编辑记录 (点击保存修改)' : '新记录';
        
        if(!isEdit) {
            document.getElementById('recordId').value = '';
            // 设置当前本地时间
            const now = new Date();
            now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
            document.getElementById('datetime').value = now.toISOString().slice(0,16);
            
            document.getElementById('duration').value = duration||15;
            document.querySelectorAll('input[type="checkbox"]').forEach(c=>c.checked=false);
            document.getElementById('experience').value='';
            document.getElementById('activityType').value='masturbation';
            document.getElementById('activityType').dispatchEvent(new Event('change'));
        }
    }

    async function saveRecord() {
        const id = document.getElementById('recordId').value;
        const acts = [];
        document.querySelectorAll('input[name="acts"]:checked').forEach(c => acts.push(c.value));
        
        // 时区转换: Local Input -> UTC ISO String
        const localVal = document.getElementById('datetime').value;
        const utcStr = new Date(localVal).toISOString();

        const data = {
          id: id||undefined,
          activity_type: document.getElementById('activityType').value,
          datetime: utcStr,
          duration: document.getElementById('duration').value,
          location: document.getElementById('location').value,
          mood: document.getElementById('mood').value,
          satisfaction: document.getElementById('satisfaction').value,
          orgasm_count: document.getElementById('orgasmCount').value,
          ejaculation_count: document.getElementById('ejaculationCount').value,
          stimulation: document.getElementById('stimulation').value,
          partner_name: document.getElementById('partnerName').value,
          sexual_position: document.getElementById('sexualPosition').value,
          experience: document.getElementById('experience').value,
          acts: acts
       };
       
       try {
           await fetch(API+'/records', { method:id?'PUT':'POST', headers: getHeaders(), body:JSON.stringify(data) });
           document.getElementById('modalOverlay').style.display = 'none';
           resetList(); loadRecords(); loadStats(); // 刷新数据
       } catch(e) { alert('保存失败'); }
    }

    // --- 其他功能 ---
    function setupInfiniteScroll() {
        const observer = new IntersectionObserver((entries) => {
            if(entries[0].isIntersecting) loadRecords();
        });
        observer.observe(document.getElementById('scrollSentinel'));
    }

    function switchView(v) {
        document.getElementById('view-home').classList.add('hidden');
        document.getElementById('view-leaderboard').classList.add('hidden');
        document.getElementById('view-'+v).classList.remove('hidden');
        if(v==='leaderboard') loadLeaderboard();
    }
    async function loadLeaderboard() {
        try {
            const r = await fetch(API+'/leaderboard', { headers: getHeaders() });
            const list = await r.json();
            const b = document.getElementById('leaderboardBody'); b.innerHTML = '';
            list.forEach((i, idx) => {
                b.insertAdjacentHTML('beforeend', \`<tr><td>\${idx+1}</td><td>\${i.username}</td><td>\${i.total_duration}</td><td>\${i.total_records}</td></tr>\`);
            });
        } catch(e){}
    }

    // 计时器逻辑
    function initTimerState() {
        const start = localStorage.getItem('timerStart');
        if(start) { startTicker(parseInt(start)); updateTimerUI(true); }
    }
    function toggleGlobalTimer() {
        const start = localStorage.getItem('timerStart');
        if(!start) {
            const now = Date.now();
            localStorage.setItem('timerStart', now);
            startTicker(now); updateTimerUI(true);
        } else {
            const min = Math.max(1, Math.round((Date.now()-parseInt(start))/60000));
            clearInterval(timerInterval);
            localStorage.removeItem('timerStart');
            updateTimerUI(false);
            openModal(false, min);
        }
    }
    function startTicker(start) {
        const el = document.getElementById('globalTimerDisplay');
        if(timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            const diff = Date.now()-start;
            const h=Math.floor(diff/3600000), m=Math.floor((diff%3600000)/60000), s=Math.floor((diff%60000)/1000);
            el.innerText = \`\${h.toString().padStart(2,'0')}:\${m.toString().padStart(2,'0')}:\${s.toString().padStart(2,'0')}\`;
        },1000);
    }
    function updateTimerUI(running) {
        const btn = document.getElementById('btnGlobalTimer');
        if(running) {
            btn.innerText = '⏹️'; btn.style.background='#333';
            document.getElementById('timer-info').style.display='flex'; document.getElementById('timer-idle').style.display='none';
        } else {
            btn.innerText = '⏱️'; btn.style.background='';
            document.getElementById('timer-info').style.display='none'; document.getElementById('timer-idle').style.display='block';
            document.getElementById('globalTimerDisplay').innerText='00:00:00';
        }
    }
    function initBackground() {
        const c = document.getElementById('bg-carousel');
        ['https://api.anosu.top/img'].forEach((u,i) => {
            const d=document.createElement('div'); d.className='bg-slide '+(i===0?'active':'');
            d.style.backgroundImage=\`url('\${u}')\`; c.appendChild(d);
        });
    }
  </script>
</body>
</html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}