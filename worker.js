/**
 * 秘密花园 (Secret Garden) - D1版
 * 数据库: Cloudflare D1 (SQLite)
 * 绑定变量名: DB
 */

const DEFAULT_JWT_SECRET = 'please-set-jwt-secret-in-env';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

// --- 翻译映射表 (保持原样用于搜索和前端显示) ---
const TR_MAP = {
  'bedroom': '卧室', 'living_room': '客厅', 'bathroom': '浴室', 'hotel': '酒店', 'car': '车内', 'outdoor': '野战',
  'office': '办公室', 'public_space': '公共场所', 'pool': '泳池', 'friend_house': '朋友家', 'other': '其他',
  'horny': '🔥 性致勃勃', 'romantic': '🌹 浪漫', 'passionate': '❤️‍🔥 激情',
  'aggressive': '😈 暴躁/发泄', 'stressed': '😫 压力释放', 'lazy': '🛌 慵懒',
  'bored': '🥱 无聊', 'happy': '🥰 开心', 'drunk': '🍷 微醺',
  'high': '🌿 嗨大了', 'experimental': '🧪 猎奇', 'morning_wood': '🌅 晨勃',
  'lonely': '🌑 孤独', 'sad': '😢 悲伤',
  'none': '纯想象', 'fantasy': '特定幻想', 
  'porn_pov': 'AV-POV', 'porn_amateur': 'AV-素人', 'porn_pro': 'AV-片商',
  'hentai': '二次元', 'erotica': '黄文', 'audio': '娇喘/ASMR', 
  'hypno': '催眠', 'cam': '网聊', 'photos': '套图', 'ntr': 'NTR', 'femdom': '女S',
  'm_hand': '传统手冲', 'm_prone': '俯卧(日地)', 'm_edging': '边缘控射',
  'm_death_grip': '死握', 'm_slow': '慢玩', 'm_prostate': '前列腺',
  'm_anal_play': '后庭把玩', 'm_docking': '夹腿',
  'toy_cup': '飞机杯', 'toy_vibe': '震动棒', 'toy_anal': '肛塞',
  'toy_milker': '榨精机', 'toy_doll': '娃娃', 'toy_lube': '大量润滑',
  'kissing': '接吻', 'cuddling': '爱抚', 'massage': '按摩', 'dirty_talk': '脏话',
  'oral_give': '口(攻)', 'oral_receive': '口(受)', '69': '69式', 'rimming': '舔肛',
  'nipple_play': '乳头刺激', 'spanking': 'SP/打屁股', 'bondage': '束缚',
  'fingering': '指交', 'manual': '手交', 'vaginal': '阴道', 'anal': '后庭',
  'facial': '颜射', 'creampie': '内射', 'swallowing': '吞精',
  'missionary': '传教士', 'doggy': '后入', 'cowgirl': '女上位',
  'reverse_cowgirl': '反向女上', 'spoons': '勺子式', 'standing': '站立',
  'prone_bone': '俯卧后入', 'legs_up': '架腿'
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    try {
      // 1. 静态页面服务
      if (path === '/' || path === '/index.html') return serveFrontend();
      
      // 2. 公开 API (注册/登录)
      if (path === '/api/auth/register') return await registerUser(request, env);
      if (path === '/api/auth/login') return await loginUser(request, env);

      // 3. 鉴权中间件
      const user = await verifyAuth(request, env);
      if (!user) return errorResponse('Unauthorized', 401);

      // 4. 受保护 API (业务逻辑)
      if (path === '/api/records') {
        if (request.method === 'GET') return await getRecords(request, env, user);
        if (request.method === 'POST') return await createRecord(request, env, user);
        if (request.method === 'PUT') return await updateRecord(request, env, user);
        if (request.method === 'DELETE') return await deleteRecord(url, env, user);
      } else if (path === '/api/statistics') {
        return await getStatistics(env, user); // 个人图表数据
      } else if (path === '/api/leaderboard') {
        return await getLeaderboard(env); // 全局排行榜
      }
      
      return new Response('Not found', { status: 404, headers: CORS_HEADERS });
    } catch (error) {
      return errorResponse(error.message, 500);
    }
  }
};

// ==========================================
// 业务逻辑 (D1 实现)
// ==========================================

// --- 获取记录列表 (支持分页与搜索) ---
async function getRecords(req, env, user) {
  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20;
  const offset = (page - 1) * limit;
  const search = (url.searchParams.get('search') || '').trim();

  let sql = `SELECT * FROM records WHERE uid = ?`;
  let params = [user.uid];

  // 如果有搜索关键词，使用 LIKE 进行模糊匹配 (匹配JSON内容或核心字段)
  if (search) {
    sql += ` AND (data_json LIKE ? OR location LIKE ? OR mood LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  // 排序与分页
  sql += ` ORDER BY datetime DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  // 执行查询
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  
  // 获取总条数用于前端分页计算
  let countSql = `SELECT count(*) as total FROM records WHERE uid = ?`;
  let countParams = [user.uid];
  if (search) {
      countSql += ` AND (data_json LIKE ? OR location LIKE ? OR mood LIKE ?)`;
      countParams.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  const countRes = await env.DB.prepare(countSql).bind(...countParams).first();
  const total = countRes.total || 0;

  // 数据格式化：将数据库中的 data_json 展开，恢复成前端需要的扁平对象
  const records = results.map(r => {
    let extra = {};
    try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    return {
      ...r,
      ...extra, // 展开 acts, toy_details 等字段
      data_json: undefined // 移除原始 JSON 字符串
    };
  });

  return jsonResponse({ 
    records, 
    pagination: { page, limit, total, pages: Math.ceil(total / limit) } 
  });
}

// --- 创建新记录 ---
async function createRecord(req, env, user) {
  const data = await req.json();
  if (!data.datetime) return errorResponse('缺少时间');

  const id = generateId();
  
  // 分离核心字段(存列)和扩展字段(存JSON)
  const core = {
      uid: user.uid,
      id: id,
      activity_type: data.activity_type,
      datetime: data.datetime,
      duration: parseInt(data.duration) || 0,
      location: data.location || 'bedroom',
      mood: data.mood || 'horny',
      satisfaction: parseInt(data.satisfaction) || 0,
      orgasm_count: parseInt(data.orgasm_count) || 0,
      ejaculation_count: parseInt(data.ejaculation_count) || 0
  };

  // 扩展字段打包
  const extra = {};
  const skipKeys = Object.keys(core).concat(['created_at']);
  for(let k in data) {
      if(!skipKeys.includes(k)) extra[k] = data[k];
  }

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

// --- 更新记录 ---
async function updateRecord(req, env, user) {
  const data = await req.json();
  if (!data.id) return errorResponse('缺少ID');

  // 验证归属权
  const existing = await env.DB.prepare('SELECT id FROM records WHERE id = ? AND uid = ?').bind(data.id, user.uid).first();
  if (!existing) return errorResponse('记录不存在或无权修改', 404);

  // 准备核心更新数据
  const coreMap = {
      activity_type: data.activity_type,
      datetime: data.datetime,
      duration: parseInt(data.duration),
      location: data.location,
      mood: data.mood,
      satisfaction: parseInt(data.satisfaction),
      orgasm_count: parseInt(data.orgasm_count),
      ejaculation_count: parseInt(data.ejaculation_count)
  };

  // 准备 JSON 更新数据
  // 注意：这里做全量 JSON 替换（假设前端传回了完整对象），如果只传了部分需先读取旧 JSON 合并
  const extra = {};
  const skipKeys = ['id', 'uid', 'created_at', ...Object.keys(coreMap)];
  for(let k in data) {
      if(!skipKeys.includes(k)) extra[k] = data[k];
  }

  await env.DB.prepare(`
    UPDATE records SET 
      activity_type = ?, datetime = ?, duration = ?, location = ?, mood = ?, 
      satisfaction = ?, orgasm_count = ?, ejaculation_count = ?, data_json = ?
    WHERE id = ? AND uid = ?
  `).bind(
    coreMap.activity_type, coreMap.datetime, coreMap.duration, coreMap.location, coreMap.mood,
    coreMap.satisfaction, coreMap.orgasm_count, coreMap.ejaculation_count, JSON.stringify(extra),
    data.id, user.uid
  ).run();

  return jsonResponse({ message: '更新成功' });
}

// --- 删除记录 ---
async function deleteRecord(url, env, user) {
  const id = url.searchParams.get('id');
  if(!id) return errorResponse('缺少ID');
  
  await env.DB.prepare('DELETE FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).run();
  return jsonResponse({ message: '删除成功' });
}

// --- 个人统计 (用于图表) ---
async function getStatistics(env, user) {
  // 1. 聚合统计
  const stats = await env.DB.prepare(`
    SELECT 
      count(*) as total_records,
      sum(case when activity_type = 'masturbation' then 1 else 0 end) as masturbation,
      sum(case when activity_type = 'intercourse' then 1 else 0 end) as intercourse,
      sum(orgasm_count) as total_orgasms,
      avg(satisfaction) as avg_satisfaction,
      avg(duration) as avg_duration
    FROM records WHERE uid = ?
  `).bind(user.uid).first();

  // 2. 按月分布 (SQLite strftime)
  const monthRes = await env.DB.prepare(`
    SELECT strftime('%Y-%m', datetime) as month, count(*) as count 
    FROM records WHERE uid = ? 
    GROUP BY month 
    ORDER BY month DESC LIMIT 12
  `).bind(user.uid).all();

  const records_by_month = {};
  // 倒序让前端图表从左到右显示旧->新
  if(monthRes.results) {
      [...monthRes.results].reverse().forEach(row => {
          if(row.month) records_by_month[row.month] = row.count;
      });
  }

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

// --- 全局排行榜 (Top 50) ---
async function getLeaderboard(env) {
  const { results } = await env.DB.prepare(`
    SELECT 
      u.username,
      count(r.id) as total_records,
      sum(r.duration) as total_duration,
      sum(case when r.activity_type = 'masturbation' then 1 else 0 end) as masturbation_count
    FROM records r
    JOIN users u ON r.uid = u.uid
    GROUP BY u.uid
    ORDER BY total_duration DESC
    LIMIT 50
  `).all();

  return jsonResponse(results);
}

// ==========================================
// 认证与工具函数
// ==========================================

async function registerUser(req, env) {
  const { username, password } = await req.json();
  if (!username || !password || username.length < 3) return errorResponse('无效的用户名或密码');
  
  // 检查重复
  const existing = await env.DB.prepare('SELECT uid FROM users WHERE username = ?').bind(username).first();
  if (existing) return errorResponse('用户名已存在');

  const uid = generateId();
  const passwordHash = await hashPassword(password);

  await env.DB.prepare('INSERT INTO users (uid, username, password_hash) VALUES (?, ?, ?)')
    .bind(uid, username, passwordHash).run();

  return jsonResponse({ message: '注册成功' });
}

async function loginUser(req, env) {
  const { username, password } = await req.json();
  
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user) return errorResponse('用户不存在', 404);

  const reqHash = await hashPassword(password);
  if (reqHash !== user.password_hash) return errorResponse('密码错误', 401);

  const token = await signJwt({ uid: user.uid, username: user.username }, env.JWT_SECRET || DEFAULT_JWT_SECRET);
  return jsonResponse({ token, username });
}

async function verifyAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.split(' ')[1];
  try { return await verifyJwt(token, env.JWT_SECRET || DEFAULT_JWT_SECRET); } catch (e) { return null; }
}

// 工具: 密码哈希 (SHA-256)
async function hashPassword(pw) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw));
  return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 工具: JWT 签名
async function signJwt(payload, secret) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+604800 })); // 7天
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`));
  return `${header}.${body}.${b64url(sig)}`;
}

// 工具: JWT 验证
async function verifyJwt(token, secret) {
  const [h, b, s] = token.split('.');
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify('HMAC', key, b64urlDecode(s), new TextEncoder().encode(`${h}.${b}`));
  if (!valid) throw new Error('Invalid signature');
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
// 前端 HTML (保持 v5.0 界面)
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
    :root {
      --primary: #ff0055; --primary-glow: rgba(255, 0, 85, 0.6);
      --secondary: #bc13fe; --glass-bg: rgba(30, 30, 40, 0.45);
      --glass-border: rgba(255, 255, 255, 0.12); --glass-blur: blur(20px);
      --text-main: #f0f0f0; 
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; }
    body { background-color: #0f0c15; color: var(--text-main); font-family: 'Noto Sans SC', sans-serif; margin: 0; padding-bottom: 110px; min-height: 100vh; overflow-x: hidden; }
    #bg-carousel { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; pointer-events: none; }
    .bg-slide { position: absolute; top: 0; left: 0; width: 100%; height: 100%; background-size: cover; background-position: center; opacity: 0; transition: opacity 3s ease-in-out; transform: scale(1.1); }
    .bg-slide.active { opacity: 1; }
    .bg-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -1; background: radial-gradient(circle at center, rgba(15,12,21,0.5) 0%, rgba(15,12,21,0.95) 100%); }
    h1, h2, h3, h4 { font-family: 'Playfair Display', serif; color: #fff; letter-spacing: 1px; }
    .container { max-width: 900px; margin: 0 auto; padding: 20px 15px; }
    .glass { background: var(--glass-bg); backdrop-filter: var(--glass-blur); -webkit-backdrop-filter: var(--glass-blur); border: 1px solid var(--glass-border); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
    .glass-panel { border-radius: 16px; padding: 15px; margin-bottom: 20px; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 1px solid var(--glass-border); padding-bottom: 10px; }
    .button { background: linear-gradient(135deg, rgba(255,0,85,0.8), rgba(188,19,254,0.8)); border: 1px solid rgba(255,255,255,0.2); border-radius: 50px; font-weight: 700; height: 3.8rem; line-height: 3.8rem; padding: 0 20px; color: #fff; text-transform: none; box-shadow: 0 4px 15px var(--primary-glow); }
    .button:active { transform: scale(0.96); }
    .button-outline { background: rgba(255,255,255,0.05); border: 1px solid var(--primary); color: var(--primary); box-shadow: none; }
    .button-small { height: 3rem; line-height: 2.8rem; padding: 0 12px; font-size: 0.9rem; }
    input, select, textarea { background-color: rgba(0, 0, 0, 0.3) !important; border: 1px solid rgba(255,255,255,0.15) !important; color: #fff !important; border-radius: 12px !important; height: 4.2rem; font-size: 1.1rem; padding-left: 12px; width: 100%; backdrop-filter: blur(5px); }
    input:focus, select:focus, textarea:focus { border-color: var(--primary) !important; box-shadow: 0 0 10px var(--primary-glow) !important; outline: none; }
    label { color: #ccc; font-size: 0.9rem; margin: 8px 0 4px; font-weight: bold; }
    #loginModal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 2000; background: #0f0c15; display: flex; align-items: center; justify-content: center; }
    .login-box { width: 90%; max-width: 400px; padding: 40px; text-align: center; background: rgba(0,0,0,0.6); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(255,255,255,0.2); }
    .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 20px; }
    .stat-item { text-align: center; padding: 10px; border-radius: 12px; background: rgba(255,255,255,0.03); }
    .stat-num { font-size: 1.4rem; color: var(--primary); display: block; font-family: 'Playfair Display'; }
    @media (max-width: 400px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
    .record-item { border-radius: 12px; margin-bottom: 12px; padding: 15px; border-left: 4px solid #555; position: relative; }
    .type-m { border-left-color: var(--secondary); background: linear-gradient(90deg, rgba(188,19,254,0.1), rgba(0,0,0,0)); }
    .type-i { border-left-color: var(--primary); background: linear-gradient(90deg, rgba(255,0,85,0.1), rgba(0,0,0,0)); }
    .tags-row { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 8px; }
    .tag { font-size: 0.75rem; padding: 2px 8px; border-radius: 8px; background: rgba(255,255,255,0.1); color: #ddd; }
    .tag-toy { color: #e056fd; border: 1px solid rgba(224,86,253,0.3); }
    #modalOverlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 1000; background: rgba(0,0,0,0.7); backdrop-filter: blur(5px); display: none; justify-content: center; align-items: flex-start; overflow-y: auto; padding: 20px 10px 100px; }
    #modalContent { width: 100%; max-width: 650px; padding: 20px; margin-top: 20px; color: #eee; }
    .section-head { color: var(--secondary); border-bottom: 1px solid rgba(255,255,255,0.1); margin: 20px 0 10px; padding-bottom: 5px; font-weight: bold; }
    .checkbox-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(85px, 1fr)); gap: 8px; margin-bottom: 10px; }
    .cb-btn input { display: none; }
    .cb-btn label { display: flex; align-items: center; justify-content: center; background: rgba(255,255,255,0.05); color: #aaa; padding: 0 4px; height: 38px; border-radius: 10px; cursor: pointer; font-size: 0.8rem; border: 1px solid rgba(255,255,255,0.1); transition: 0.2s; }
    .cb-btn input:checked + label { background: var(--primary); color: #fff; border-color: var(--primary); box-shadow: 0 0 10px var(--primary-glow); }
    .form-row { display: flex; gap: 10px; } .form-col { flex: 1; }
    .hidden { display: none !important; }
    .rank-table { width: 100%; border-collapse: separate; border-spacing: 0 8px; }
    .rank-table th { color: #aaa; font-weight: 300; font-size: 0.8rem; text-align: left; padding: 0 10px; }
    .rank-table td { background: rgba(255,255,255,0.05); padding: 15px 10px; color: #fff; }
    .rank-table tr td:first-child { border-top-left-radius: 10px; border-bottom-left-radius: 10px; font-weight: bold; color: var(--primary); }
    .rank-table tr td:last-child { border-top-right-radius: 10px; border-bottom-right-radius: 10px; }
    #timer-bar { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); width: 90%; max-width: 600px; z-index: 99; border-radius: 50px; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; }
    .timer-display-main { font-family: monospace; font-size: 1.4rem; font-weight: bold; color: #fff; text-shadow: 0 0 10px var(--primary); }
  </style>
</head>
<body>
  <div id="bg-carousel"></div>
  <div class="bg-overlay"></div>
  <div id="loginModal">
    <div class="login-box glass">
      <h2 style="margin-bottom:30px; text-shadow:0 0 10px var(--primary);">Secret Garden</h2>
      <input type="text" id="lg-user" placeholder="用户名" style="margin-bottom:15px;">
      <input type="password" id="lg-pass" placeholder="密码" style="margin-bottom:25px;">
      <button class="button" style="width:100%; margin-bottom:15px;" onclick="doLogin()">登 录</button>
      <button class="button button-outline" style="width:100%;" onclick="doRegister()">注 册</button>
      <div id="loginMsg" style="margin-top:15px; color: var(--primary);"></div>
    </div>
  </div>
  <div class="container" id="app" style="filter: blur(10px);">
    <header>
      <h1>秘密花园</h1>
      <div><span id="welcomeUser" style="font-size:0.9rem; margin-right:10px; color:#ccc;"></span><button class="button button-small button-outline" onclick="logout()">退出</button></div>
    </header>
    <div style="display:flex; gap:10px; overflow-x:auto; margin-bottom:15px; padding-bottom:5px;">
      <button class="button button-small" onclick="switchView('home')">🏠 统计 & 记录</button>
      <button class="button button-small button-outline" onclick="switchView('leaderboard')">🏆 极乐排行榜</button>
      <button class="button button-small button-outline" onclick="openModal(false)">+ 补录</button>
    </div>
    <div id="view-home">
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
           <input type="text" id="searchInput" placeholder="🔍 搜索玩法、心情、玩具..." style="height:3.6rem;">
           <button class="button button-small" onclick="loadPage(1, document.getElementById('searchInput').value)">搜索</button>
        </div>
        <div id="listContainer">加载中...</div>
        <div id="pagination" style="display: flex; justify-content: center; gap: 5px; margin-top: 20px;"></div>
    </div>
    <div id="view-leaderboard" class="hidden">
        <div class="glass glass-panel">
            <h3 style="border-bottom:1px solid rgba(255,255,255,0.1); padding-bottom:10px;">🏆 极乐榜 (Top 50)</h3>
            <table class="rank-table"><thead><tr><th>排名</th><th>玩家</th><th>总时长(分)</th><th>自慰/总次</th></tr></thead><tbody id="leaderboardBody"></tbody></table>
        </div>
    </div>
  </div>
  <div id="timer-bar" class="glass">
      <div id="timer-info" style="display:none; flex-direction:column;"><span style="font-size:0.7rem; color:#aaa; letter-spacing:1px;">SESSION TIME</span><span id="globalTimerDisplay" class="timer-display-main">00:00:00</span></div>
      <div id="timer-idle" style="font-size:1.1rem; color:#ddd; font-weight:bold;">准备好了吗?</div>
      <button id="btnGlobalTimer" class="button button-small" style="height:3.5rem; border-radius:30px;" onclick="toggleGlobalTimer()">⏱️ 开始</button>
  </div>
  <div id="modalOverlay">
    <div id="modalContent" class="glass glass-panel">
      <h3 id="formTitle" style="margin-top:0; border-bottom: 1px solid rgba(255,255,255,0.1); padding-bottom: 10px;">记录详情</h3>
      <input type="hidden" id="recordId">
      <div class="form-row"><div class="form-col"><label>类型</label><select id="activityType"><option value="masturbation">🖐 自慰 (Solo)</option><option value="intercourse">👩‍❤️‍👨 性爱 (Partner)</option></select></div><div class="form-col"><label>时间</label><input type="datetime-local" id="datetime"></div></div>
      <div class="form-row"><div class="form-col"><label>地点</label><select id="location"><option value="bedroom">卧室</option><option value="living_room">客厅</option><option value="bathroom">浴室</option><option value="hotel">酒店</option><option value="car">车内</option><option value="outdoor">野战</option><option value="office">办公室</option><option value="other">其他</option></select></div><div class="form-col"><label>心情</label><select id="mood"><option value="horny">🔥 性致勃勃</option><option value="lonely">🌑 孤独/求安慰</option><option value="stressed">😫 压力释放</option><option value="bored">🥱 无聊消遣</option><option value="high">🌿 嗨大/致幻</option><option value="drunk">🍷 微醺/醉酒</option><option value="morning_wood">🌅 晨勃</option></select></div></div>
      <div id="sectionMasturbation"><div class="section-head">🎬 助兴材料</div><select id="stimulation"><option value="none">无 / 纯想象</option><option value="porn_pov">AV - POV/第一人称</option><option value="porn_amateur">AV - 素人/自拍</option><option value="porn_pro">AV - 专业片商</option><option value="hentai">二次元 / 里番</option><option value="erotica">文学 / 黄文</option><option value="audio">音频 / 娇喘 / ASMR</option><option value="cam">网聊 / 裸聊</option><option value="photos">图片 / 写真</option><option value="fantasy">特定性幻想</option></select><div class="section-head">🖐 玩法与技巧</div><div class="checkbox-grid"><div class="cb-btn"><input type="checkbox" id="m_hand" value="m_hand"><label for="m_hand">传统手冲</label></div><div class="cb-btn"><input type="checkbox" id="m_edging" value="m_edging"><label for="m_edging">边缘控射</label></div><div class="cb-btn"><input type="checkbox" id="m_slow" value="m_slow"><label for="m_slow">慢玩</label></div><div class="cb-btn"><input type="checkbox" id="m_prone" value="m_prone"><label for="m_prone">俯卧/日地</label></div><div class="cb-btn"><input type="checkbox" id="m_death" value="m_death_grip"><label for="m_death">死握(强)</label></div><div class="cb-btn"><input type="checkbox" id="m_prostate" value="m_prostate"><label for="m_prostate">前列腺</label></div><div class="cb-btn"><input type="checkbox" id="m_anal" value="m_anal_play"><label for="m_anal">后庭把玩</label></div></div><div class="section-head">🧩 玩具使用</div><div class="checkbox-grid"><div class="cb-btn"><input type="checkbox" id="toy_cup" value="toy_cup"><label for="toy_cup">飞机杯</label></div><div class="cb-btn"><input type="checkbox" id="toy_vibe" value="toy_vibe"><label for="toy_vibe">震动棒</label></div><div class="cb-btn"><input type="checkbox" id="toy_anal" value="toy_anal"><label for="toy_anal">肛塞</label></div><div class="cb-btn"><input type="checkbox" id="toy_lube" value="toy_lube"><label for="toy_lube">大量润滑</label></div></div></div>
      <div id="sectionIntercourse" class="hidden"><div class="section-head">❤ 伴侣与互动</div><div class="form-row"><div class="form-col"><label>伴侣</label><input type="text" id="partnerName" placeholder="名字"></div><div class="form-col"><label>发起</label><select id="initiator"><option value="both">自然</option><option value="me">我</option><option value="partner">对方</option></select></div></div><div class="section-head">前戏与行为</div><div class="checkbox-grid"><div class="cb-btn"><input type="checkbox" id="act_kiss" value="kissing"><label for="act_kiss">接吻</label></div><div class="cb-btn"><input type="checkbox" id="act_oral_g" value="oral_give"><label for="act_oral_g">口(攻)</label></div><div class="cb-btn"><input type="checkbox" id="act_oral_r" value="oral_receive"><label for="act_oral_r">口(受)</label></div><div class="cb-btn"><input type="checkbox" id="act_69" value="69"><label for="act_69">69</label></div><div class="cb-btn"><input type="checkbox" id="act_fing" value="fingering"><label for="act_fing">指交</label></div><div class="cb-btn"><input type="checkbox" id="act_vag" value="vaginal"><label for="act_vag">阴道</label></div><div class="cb-btn"><input type="checkbox" id="act_anal" value="anal"><label for="act_anal">后庭</label></div><div class="cb-btn"><input type="checkbox" id="act_creampie" value="creampie"><label for="act_creampie">内射</label></div></div><div class="form-row"><div class="form-col"><label>体位</label><select id="sexualPosition"><option value="">--选择--</option><option value="missionary">传教士</option><option value="doggy">后入</option><option value="cowgirl">女上位</option><option value="prone_bone">俯卧后入</option></select></div></div></div>
      <div class="section-head">📊 结果</div><div class="form-row"><div class="form-col"><label>时长: <span id="valDuration" style="color:var(--primary);">0</span> 分钟</label><input type="range" id="duration" min="0" max="180" value="15" oninput="document.getElementById('valDuration').innerText=this.value"></div><div class="form-col"><label>满意度: <span id="valScore" style="color:var(--primary);">5</span></label><input type="range" id="satisfaction" min="1" max="10" value="5" oninput="document.getElementById('valScore').innerText=this.value"></div></div><div class="form-row"><div class="form-col"><label>高潮次数</label><input type="number" id="orgasmCount" value="1" min="0"></div><div class="form-col"><label>射精次数</label><input type="number" id="ejaculationCount" value="1" min="0"></div></div>
      <input type="text" id="toyDetails" placeholder="补充玩具详情..." style="margin-top:10px;"><textarea id="experience" placeholder="备注 / 体验详情..." style="min-height: 80px; margin-top:10px;"></textarea>
      <div style="display: flex; gap: 10px; margin-top: 20px;"><button class="button button-outline" style="flex:1" onclick="document.getElementById('modalOverlay').style.display='none'">取消</button><button class="button" style="flex:2" onclick="saveRecord()">保存记录</button></div>
    </div>
  </div>
  <script>
    const API = '/api';
    const TR_MAP = ${JSON.stringify(TR_MAP)};
    function tr(k) { return TR_MAP[k] || k; }
    const BG_IMGS = ['https://api.anosu.top/img'];
    let token = localStorage.getItem('sg_token');
    let user = localStorage.getItem('sg_user');
    let timerInterval = null, chart1, chart2;
    (function() {
      initBackground(); initTimerState();
      if(token) {
        document.getElementById('loginModal').style.display = 'none';
        document.getElementById('app').style.filter = 'none';
        document.getElementById('welcomeUser').innerText = user;
        loadFullData();
      }
      document.getElementById('activityType').addEventListener('change', e => {
         const isM = e.target.value === 'masturbation';
         document.getElementById('sectionMasturbation').classList.toggle('hidden', !isM);
         document.getElementById('sectionIntercourse').classList.toggle('hidden', isM);
      });
    })();
    function getHeaders() { return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }; }
    async function doLogin() {
        try {
            const u = document.getElementById('lg-user').value;
            const p = document.getElementById('lg-pass').value;
            const r = await fetch(API+'/auth/login', { method:'POST', body:JSON.stringify({username:u, password:p}) });
            const d = await r.json();
            if(d.error) throw new Error(d.error);
            token=d.token; user=d.username;
            localStorage.setItem('sg_token', token); localStorage.setItem('sg_user', user);
            location.reload();
        } catch(e){ document.getElementById('loginMsg').innerText=e.message; }
    }
    async function doRegister() {
        try {
            const u = document.getElementById('lg-user').value;
            const p = document.getElementById('lg-pass').value;
            const r = await fetch(API+'/auth/register', { method:'POST', body:JSON.stringify({username:u, password:p}) });
            const d = await r.json();
            if(d.error) throw new Error(d.error);
            alert('注册成功，请登录');
        } catch(e){ document.getElementById('loginMsg').innerText=e.message; }
    }
    function logout() { localStorage.clear(); location.reload(); }
    function switchView(v) {
        document.getElementById('view-home').classList.add('hidden');
        document.getElementById('view-leaderboard').classList.add('hidden');
        document.getElementById('view-'+v).classList.remove('hidden');
        if(v==='leaderboard') loadLeaderboard();
    }
    async function loadFullData() { await Promise.all([loadStats(), loadPage(1, '')]); }
    async function loadStats() {
        try {
            const r = await fetch(API+'/statistics', { headers: getHeaders() });
            const s = await r.json();
            if(s.error === 'Unauthorized') return logout();
            document.getElementById('sTotal').innerText = s.total_records;
            document.getElementById('sDuration').innerText = s.avg_duration;
            document.getElementById('sScore').innerText = s.avg_satisfaction;
            document.getElementById('sOrgasm').innerText = s.total_orgasms;
            renderCharts(s);
        } catch(e){}
    }
    async function loadPage(page, search) {
        try {
            const r = await fetch(\`\${API}/records?page=\${page}&limit=20&search=\${search}\`, { headers: getHeaders() });
            const d = await r.json();
            renderList(d.records);
            renderPagination(d.pagination, search);
        } catch(e) {}
    }
    async function loadLeaderboard() {
        try {
            const r = await fetch(API+'/leaderboard', { headers: getHeaders() });
            const list = await r.json();
            const b = document.getElementById('leaderboardBody'); b.innerHTML = '';
            list.forEach((i, idx) => {
                const badge = idx===0?'🥇':(idx===1?'🥈':(idx===2?'🥉':idx+1));
                b.insertAdjacentHTML('beforeend', \`<tr><td>\${badge}</td><td>\${i.username}</td><td>\${i.total_duration}</td><td>\${i.masturbation_count} / \${i.total_records}</td></tr>\`);
            });
        } catch(e){}
    }
    function renderList(list) {
        const c = document.getElementById('listContainer'); c.innerHTML = '';
        if(!list.length) return c.innerHTML = '<div style="text-align:center;color:#999;margin-top:20px">暂无记录</div>';
        list.forEach(item => {
            const isM = item.activity_type === 'masturbation';
            const d = new Date(item.datetime);
            const dateStr = \`\${d.getMonth()+1}月\${d.getDate()}日 \${String(d.getHours()).padStart(2,'0')}:\${String(d.getMinutes()).padStart(2,'0')}\`;
            let tags = item.location ? \`<span class="tag">\${tr(item.location)}</span>\` : '';
            if(isM && item.stimulation && item.stimulation!=='none') tags+=\`<span class="tag">\${tr(item.stimulation)}</span>\`;
            if(item.acts) item.acts.slice(0,4).forEach(a => {
                const isToy = a.startsWith('toy_');
                tags+=\`<span class="tag \${isToy?'tag-toy':''} ">\${tr(a)}</span>\`;
            });
            c.insertAdjacentHTML('beforeend', \`
               <div class="glass record-item \${isM?'type-m':'type-i'}">
                  <div style="display:flex;justify-content:space-between;color:#fff;font-weight:bold;margin-bottom:5px;">
                     <span>\${isM?'🖐 自慰':'❤️ 性爱'}</span>
                     <div style="font-size:0.8rem;color:#aaa;">
                        <span onclick="deleteRecord('\${item.id}')" style="cursor:pointer;">删除</span>
                     </div>
                  </div>
                  <div style="font-size:0.9rem;color:#ccc;margin-bottom:8px;">\${dateStr} · \${item.duration}分 · \${item.satisfaction}分</div>
                  <div class="tags-row">\${tags}</div>
               </div>\`);
        });
    }
    function renderPagination(p, s) {
        const div = document.getElementById('pagination'); div.innerHTML = '';
        if(p.pages<=1) return;
        const btn = (i,t) => \`<div class="page-btn" style="background:\${i===p.page?'var(--primary)':'rgba(255,255,255,0.1)'};padding:5px 12px;border-radius:8px;cursor:pointer;" onclick="loadPage(\${i},'\${s}')">\${t||i}</div>\`;
        if(p.page>1) div.innerHTML+=btn(p.page-1,'←');
        for(let i=Math.max(1,p.page-2); i<=Math.min(p.pages,p.page+2); i++) div.innerHTML+=btn(i);
        if(p.page<p.pages) div.innerHTML+=btn(p.page+1,'→');
    }
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
            btn.innerText = '⏹️ 结束'; btn.style.background='#333';
            document.getElementById('timer-info').style.display='flex'; document.getElementById('timer-idle').style.display='none';
        } else {
            btn.innerText = '⏱️ 开始'; btn.style.background='';
            document.getElementById('timer-info').style.display='none'; document.getElementById('timer-idle').style.display='block';
            document.getElementById('globalTimerDisplay').innerText='00:00:00';
        }
    }
    function openModal(isEdit, duration) {
        document.getElementById('modalOverlay').style.display = 'flex';
        document.getElementById('recordId').value = '';
        document.getElementById('formTitle').innerText = '新记录';
        const now = new Date(); now.setMinutes(now.getMinutes()-now.getTimezoneOffset());
        document.getElementById('datetime').value = now.toISOString().slice(0,16);
        document.getElementById('duration').value = duration||15;
        document.getElementById('valDuration').innerText = duration||15;
        document.querySelectorAll('input[type="checkbox"]').forEach(c=>c.checked=false);
        document.getElementById('activityType').value='masturbation';
        document.getElementById('activityType').dispatchEvent(new Event('change'));
    }
    async function saveRecord() {
        const id = document.getElementById('recordId').value;
        const acts = [];
        document.querySelectorAll('.checkbox-grid input:checked').forEach(c => acts.push(c.value));
        const data = {
          id: id||undefined,
          activity_type: document.getElementById('activityType').value,
          datetime: document.getElementById('datetime').value,
          duration: document.getElementById('duration').value,
          location: document.getElementById('location').value,
          mood: document.getElementById('mood').value,
          satisfaction: document.getElementById('satisfaction').value,
          orgasm_count: document.getElementById('orgasmCount').value,
          ejaculation_count: document.getElementById('ejaculationCount').value,
          stimulation: document.getElementById('stimulation').value,
          partner_name: document.getElementById('partnerName').value,
          initiator: document.getElementById('initiator').value,
          sexual_position: document.getElementById('sexualPosition').value,
          toy_details: document.getElementById('toyDetails').value,
          experience: document.getElementById('experience').value,
          acts: acts
       };
       try {
           await fetch(API+'/records', { method:id?'PUT':'POST', headers: getHeaders(), body:JSON.stringify(data) });
           document.getElementById('modalOverlay').style.display = 'none';
           loadFullData();
       } catch(e) { alert('保存失败'); }
    }
    async function deleteRecord(id) {
        if(confirm('确定删除?')) { await fetch(API+'/records?id='+id, {method:'DELETE', headers:getHeaders()}); loadFullData(); }
    }
    function renderCharts(s) {
       Chart.defaults.color='#ccc'; Chart.defaults.borderColor='rgba(255,255,255,0.1)';
       if(chart1) chart1.destroy();
       chart1=new Chart(document.getElementById('chartType'),{type:'doughnut',data:{labels:['自慰','性爱'],datasets:[{data:[s.masturbation,s.intercourse],backgroundColor:['#bc13fe','#ff0055'],borderWidth:0}]},options:{maintainAspectRatio:false,plugins:{legend:{position:'bottom'}}}});
       if(chart2) chart2.destroy();
       const m=Object.keys(s.records_by_month).sort().slice(-6);
       chart2=new Chart(document.getElementById('chartHistory'),{type:'bar',data:{labels:m,datasets:[{label:'次数',data:m.map(k=>s.records_by_month[k]),backgroundColor:'#ff0055',borderRadius:4}]},options:{maintainAspectRatio:false,scales:{x:{grid:{display:false}},y:{grid:{color:'rgba(255,255,255,0.05)'}}},plugins:{legend:{display:false}}}});
    }
    function initBackground() {
        const c = document.getElementById('bg-carousel');
        BG_IMGS.forEach((u,i) => {
            const d=document.createElement('div'); d.className='bg-slide '+(i===0?'active':'');
            d.style.backgroundImage=\`url('\${u}')\`; c.appendChild(d);
        });
        let idx=0; setInterval(()=>{
            const s=document.querySelectorAll('.bg-slide'); s[idx].classList.remove('active');
            idx=(idx+1)%s.length; s[idx].classList.add('active');
        }, 12000);
    }
  </script>
</body>
</html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}