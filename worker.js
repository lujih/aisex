/**
 * 秘密花园 (Secret Garden) - v7.5 Admin Edition
 * 特性: 导航栏融合设计 + 管理员后台 + 全中文化 + 沉浸式体验
 */

const DEFAULT_JWT_SECRET = 'change-this-secret-in-env-vars-please'; 
const DEFAULT_ADMIN_PASS = '123456'; // 默认管理密码

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Admin-Pass',
  'Access-Control-Max-Age': '86400',
};

// --- 翻译映射表 ---
const TR_MAP = {
  'bedroom': '卧室', 'living_room': '客厅', 'bathroom': '浴室', 'hotel': '酒店', 'car': '车内', 'outdoor': '野战', 'office': '办公室', 'public_space': '公共场所', 'pool': '泳池', 'friend_house': '朋友家', 'other': '其他',
  'horny': '🔥 性致勃勃', 'romantic': '🌹 浪漫', 'passionate': '❤️‍🔥 激情', 'aggressive': '😈 暴躁/发泄', 'stressed': '😫 压力释放', 'lazy': '🛌 慵懒', 'bored': '🥱 无聊', 'happy': '🥰 开心', 'drunk': '🍷 微醺', 'high': '🌿 嗨大了', 'experimental': '🧪 猎奇', 'morning_wood': '🌅 晨勃', 'lonely': '🌑 孤独', 'sad': '😢 悲伤', 'none': '纯想象', 'fantasy': '特定幻想', 
  'porn_pov': '第一人称(POV)', 'porn_amateur': '素人/自拍', 'porn_pro': '专业片商', 'hentai': '二次元/里番', 'erotica': '色情文学', 'audio': '娇喘/ASMR', 'hypno': '催眠', 'cam': '网聊/直播', 'photos': '写真套图',
  'm_hand': '传统手艺', 'm_lube': '润滑液', 'm_fast': '快速冲刺', 'm_slow': '慢玩享受', 'm_edging': '边缘控射(寸止)', 'm_prostate': '前列腺开发', 'm_anal': '后庭探索',
  'toy_cup': '飞机杯', 'toy_vibe': '震动棒', 'toy_milker': '榨精机', 'toy_doll': '实体娃娃',
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
      
      // Admin Routes
      if (path.startsWith('/api/admin')) return await handleAdmin(request, env);

      // Auth Routes
      if (path === '/api/auth/register') return await registerUser(request, env);
      if (path === '/api/auth/login') return await loginUser(request, env);

      // User Routes (Protected)
      const user = await verifyAuth(request, env);
      if (!user) return errorResponse('Unauthorized', 401);

      if (path === '/api/auth/password') return await changePassword(request, env, user);
      
      if (path === '/api/records') {
        if (request.method === 'GET') return await getRecords(request, env, user);
        if (request.method === 'POST') return await createRecord(request, env, user);
        if (request.method === 'PUT') return await updateRecord(request, env, user);
        if (request.method === 'DELETE') return await deleteRecord(url, env, user);
      } 
      else if (path === '/api/records/detail') return await getRecordDetail(url, env, user);
      else if (path === '/api/statistics') return await getStatistics(url, env, user);
      else if (path === '/api/leaderboard') return await getLeaderboard(env);
      
      return new Response('Not found', { status: 404, headers: CORS_HEADERS });
    } catch (error) { return errorResponse(error.message, 500); }
  }
};

// --- 后端逻辑 ---

// Admin Handler
async function handleAdmin(req, env) {
    const adminPass = env.ADMIN_PASSWORD || DEFAULT_ADMIN_PASS;
    const providedPass = req.headers.get('X-Admin-Pass');
    
    // 简单的密码验证
    if (providedPass !== adminPass) return errorResponse('管理员密码错误', 403);

    const url = new URL(req.url);
    const path = url.pathname;

    if (path === '/api/admin/stats') {
        // 获取系统级统计
        const userCount = await env.DB.prepare('SELECT count(*) as c FROM users').first();
        const recordCount = await env.DB.prepare('SELECT count(*) as c FROM records').first();
        return jsonResponse({
            users: userCount.c,
            records: recordCount.c,
            db_size_est: (recordCount.c * 0.5).toFixed(2) + ' KB' // 粗略估算
        });
    }

    if (path === '/api/admin/users') {
        if (req.method === 'GET') {
            const { results } = await env.DB.prepare('SELECT uid, username, created_at, (SELECT count(*) FROM records WHERE records.uid = users.uid) as rec_count FROM users ORDER BY rec_count DESC').all();
            return jsonResponse(results);
        }
        if (req.method === 'DELETE') {
            const uid = url.searchParams.get('uid');
            if(!uid) return errorResponse('缺少UID');
            await env.DB.prepare('DELETE FROM records WHERE uid = ?').bind(uid).run();
            await env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(uid).run();
            return jsonResponse({ message: '用户及其数据已删除' });
        }
    }
    return errorResponse('Admin route not found', 404);
}

// User Data Handlers
async function getRecords(req, env, user) {
  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20; const offset = (page - 1) * limit;
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
  const records = results.map(r => {
    let extra = {}; try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    return { ...r, ...extra, data_json: undefined };
  });
  return jsonResponse({ records, page });
}

async function getRecordDetail(url, env, user) {
    const id = url.searchParams.get('id');
    const r = await env.DB.prepare('SELECT * FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).first();
    if (!r) return errorResponse('记录不存在', 404);
    let extra = {}; try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    return jsonResponse({ ...r, ...extra, data_json: undefined });
}

async function createRecord(req, env, user) {
  const data = await req.json();
  const id = generateId();
  const { core, extra } = splitData(data, user.uid, id);
  await env.DB.prepare(`INSERT INTO records (id, uid, activity_type, datetime, duration, location, mood, satisfaction, orgasm_count, ejaculation_count, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(core.id, core.uid, core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra), new Date().toISOString()).run();
  return jsonResponse({ message: '创建成功', id });
}

async function updateRecord(req, env, user) {
  const data = await req.json();
  if (!data.id) return errorResponse('缺少ID');
  const existing = await env.DB.prepare('SELECT id FROM records WHERE id = ? AND uid = ?').bind(data.id, user.uid).first();
  if (!existing) return errorResponse('无权修改', 403);
  const { core, extra } = splitData(data, user.uid, data.id);
  await env.DB.prepare(`UPDATE records SET activity_type = ?, datetime = ?, duration = ?, location = ?, mood = ?, satisfaction = ?, orgasm_count = ?, ejaculation_count = ?, data_json = ? WHERE id = ? AND uid = ?`).bind(core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra), core.id, core.uid).run();
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
  if (range === 'month') timeFilter = " AND datetime >= datetime('now', 'start of month')";
  else if (range === 'year') timeFilter = " AND datetime >= datetime('now', '-1 year')";
  else if (range === '3_months') timeFilter = " AND datetime >= datetime('now', '-3 months')";
  const sql = `SELECT count(*) as total_records, sum(case when activity_type = 'masturbation' then 1 else 0 end) as masturbation, sum(case when activity_type = 'intercourse' then 1 else 0 end) as intercourse, sum(orgasm_count) as total_orgasms, avg(satisfaction) as avg_satisfaction, avg(duration) as avg_duration FROM records WHERE uid = ? ${timeFilter}`;
  const stats = await env.DB.prepare(sql).bind(user.uid).first();
  const monthSql = `SELECT strftime('%Y-%m', datetime) as month, count(*) as count FROM records WHERE uid = ? ${timeFilter} GROUP BY month ORDER BY month DESC LIMIT 12`;
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
    const { results } = await env.DB.prepare(`SELECT u.username, count(r.id) as total_records, sum(r.duration) as total_duration FROM records r JOIN users u ON r.uid = u.uid GROUP BY u.uid ORDER BY total_duration DESC LIMIT 50`).all();
    return jsonResponse(results);
}

// User & Auth
async function registerUser(req, env) {
  const { username, password } = await req.json();
  if (!username || !password || username.length < 3) return errorResponse('无效参数');
  try { await env.DB.prepare('INSERT INTO users (uid, username, password_hash, created_at) VALUES (?, ?, ?, ?)').bind(generateId(), username, await hashPassword(password), new Date().toISOString()).run(); return jsonResponse({ message: '注册成功' }); } catch (e) { return errorResponse('用户名已存在'); }
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
  const dbUser = await env.DB.prepare('SELECT password_hash FROM users WHERE uid = ?').bind(user.uid).first();
  if((await hashPassword(oldPassword)) !== dbUser.password_hash) return errorResponse('旧密码错误', 403);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE uid = ?').bind(await hashPassword(newPassword), user.uid).run();
  return jsonResponse({ message: '修改成功' });
}

// Utils
function splitData(data, uid, id) {
    const coreMap = ['activity_type','datetime','duration','location','mood','satisfaction','orgasm_count','ejaculation_count'];
    const core = { uid, id, duration:0, satisfaction:0, orgasm_count:0, ejaculation_count:0 };
    const extra = {};
    for (let k in data) { if (coreMap.includes(k)) core[k] = data[k]; else if (k !== 'id' && k !== 'uid' && k !== 'created_at') extra[k] = data[k]; }
    ['duration','satisfaction','orgasm_count','ejaculation_count'].forEach(k => core[k] = parseInt(core[k]) || 0);
    return { core, extra };
}
async function hashPassword(pw) { const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw)); return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function verifyAuth(request, env) { const h = request.headers.get('Authorization'); if (!h || !h.startsWith('Bearer ')) return null; try { return await verifyJwt(h.split(' ')[1], env.JWT_SECRET || DEFAULT_JWT_SECRET); } catch (e) { return null; } }
async function signJwt(payload, secret) { const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })); const b = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+604800 })); const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(`${h}.${b}`)); return `${h}.${b}.${b64url(s)}`; }
async function verifyJwt(token, secret) { const [h, b, s] = token.split('.'); const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']); if (!await crypto.subtle.verify('HMAC', k, b64urlDecode(s), new TextEncoder().encode(`${h}.${b}`))) throw new Error('Invalid'); const p = JSON.parse(new TextDecoder().decode(b64urlDecode(b))); if (p.exp < Date.now()/1000) throw new Error('Expired'); return p; }
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
  <meta name="theme-color" content="#050505">
  <title>Secret Garden</title>
  <link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@300;400;500;700&family=Cinzel:wght@400;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-deep: #050505;
      --primary: #d946ef; --secondary: #8b5cf6; --accent: #f43f5e;
      --glass-surface: rgba(25, 25, 30, 0.75); --glass-border: rgba(255, 255, 255, 0.1);
      --text-main: #f3f4f6; --text-muted: #9ca3af;
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
    body { margin: 0; background-color: var(--bg-deep); color: var(--text-main); font-family: 'Noto Sans SC', sans-serif; min-height: 100vh; padding-bottom: 95px; }
    
    .ambient-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; background: radial-gradient(circle at 10% 20%, #1a0b2e 0%, transparent 40%), radial-gradient(circle at 90% 80%, #2e0b1f 0%, transparent 40%), linear-gradient(to bottom, #0a0a0a, #050505); }
    
    /* 核心组件 */
    .glass { background: var(--glass-surface); backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px); border: 1px solid var(--glass-border); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
    .card { border-radius: 16px; padding: 20px; margin-bottom: 15px; position: relative; overflow: hidden; }
    .btn { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border: none; border-radius: 12px; padding: 12px; font-weight: 600; width: 100%; cursor: pointer; transition: 0.2s; box-shadow: 0 4px 15px rgba(217, 70, 239, 0.3); }
    .btn:active { transform: scale(0.97); }
    .btn-outline { background: transparent; border: 1px solid rgba(255,255,255,0.2); box-shadow: none; }
    .btn-danger { background: linear-gradient(135deg, #ef4444, #b91c1c); box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    .hidden { display: none !important; }
    
    /* 图表自适应布局 */
    .charts-wrapper { display: flex; flex-direction: row; gap: 15px; height: 220px; padding: 15px; }
    .chart-box-main { flex: 2; position: relative; min-width: 0; display: flex; align-items: center; }
    .chart-box-side { flex: 1; position: relative; max-width: 180px; display: flex; align-items: center; justify-content: center; }
    
    @media (max-width: 600px) {
        .charts-wrapper { flex-direction: column; height: auto; }
        .chart-box-main { width: 100%; height: 200px; flex: none; }
        .chart-box-side { width: 100%; height: 180px; max-width: none; flex: none; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 10px; padding-top: 10px; }
    }

    /* 沉浸式计时器全屏层 */
    #immersiveTimer { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #000; z-index: 2000; display: none; flex-direction: column; align-items: center; justify-content: center; }
    .timer-display { font-family: 'Cinzel', monospace; font-size: 4rem; font-weight: bold; color: #fff; text-shadow: 0 0 20px var(--primary); margin-bottom: 40px; font-variant-numeric: tabular-nums; }
    .timer-btn-stop { width: 80px; height: 80px; border-radius: 50%; border: 2px solid var(--accent); background: rgba(244, 63, 94, 0.1); color: var(--accent); font-size: 1.5rem; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.3s; }
    .timer-btn-stop:active { background: var(--accent); color: #fff; transform: scale(0.9); }
    .pulse-ring { position: absolute; width: 200px; height: 200px; border-radius: 50%; border: 1px solid rgba(217, 70, 239, 0.3); animation: pulse 2s infinite; z-index: -1; }
    @keyframes pulse { 0% { transform: scale(0.8); opacity: 1; } 100% { transform: scale(1.5); opacity: 0; } }

    /* 时光轴 */
    .timeline { position: relative; padding-left: 20px; border-left: 2px solid rgba(255,255,255,0.1); margin-left: 10px; }
    .timeline-item { position: relative; margin-bottom: 30px; }
    .timeline-dot { position: absolute; left: -26px; top: 0; width: 10px; height: 10px; border-radius: 50%; background: var(--bg-deep); border: 2px solid var(--primary); }
    .timeline-date { font-size: 0.8rem; color: var(--primary); font-weight: bold; margin-bottom: 5px; }
    .timeline-content { background: rgba(255,255,255,0.03); border-radius: 12px; padding: 12px; border: 1px solid rgba(255,255,255,0.05); }

    /* 底部 Dock - 优化版 (扁平化集成) */
    .dock-nav { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); width: 95%; max-width: 480px; height: 60px; background: rgba(20, 20, 25, 0.9); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 30px; display: flex; justify-content: space-evenly; align-items: center; z-index: 100; box-shadow: 0 10px 30px rgba(0,0,0,0.6); padding: 0 5px; }
    .dock-item { display: flex; flex-direction: column; align-items: center; justify-content: center; color: #666; font-size: 0.65rem; gap: 3px; transition: 0.3s; width: 60px; height: 100%; cursor: pointer; position: relative; }
    .dock-item svg { width: 22px; height: 22px; stroke: currentColor; stroke-width: 2; fill: none; transition: 0.3s; }
    .dock-item.active { color: var(--primary); }
    .dock-item.active svg { transform: translateY(-3px); stroke: var(--primary); }
    
    /* 计时器按钮 (中间项) */
    .dock-item.timer-btn { color: var(--accent); }
    .dock-item.timer-btn svg { width: 28px; height: 28px; filter: drop-shadow(0 0 5px rgba(244, 63, 94, 0.4)); }
    .dock-item.timer-btn.active { color: #fff; }
    .dock-item.timer-btn:active svg { transform: scale(0.9); }

    /* 通用样式补全 */
    .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
    .stat-box { background: rgba(255,255,255,0.03); padding: 15px; border-radius: 16px; text-align: center; border: 1px solid rgba(255,255,255,0.05); }
    .stat-val { font-family: 'Cinzel', serif; font-size: 1.6rem; color: #fff; text-shadow: 0 0 10px rgba(255,255,255,0.3); }
    .stat-label { font-size: 0.7rem; color: var(--text-muted); margin-top: 4px; }
    
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 200; background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); display: none; align-items: flex-end; justify-content: center; }
    .modal-content { width: 100%; max-width: 600px; background: #111; border-radius: 24px 24px 0 0; padding: 25px 20px 40px; max-height: 90vh; overflow-y: auto; border-top: 1px solid #333; animation: slideUp 0.3s ease; }
    @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }

    .segment-control { display: flex; background: #222; border-radius: 12px; padding: 4px; margin-bottom: 20px; border: 1px solid #333; }
    .segment-opt { flex: 1; text-align: center; padding: 10px; border-radius: 10px; color: #888; font-weight: 600; cursor: pointer; transition: 0.3s; }
    .segment-opt.active { background: #333; color: #fff; }
    .segment-opt.active[data-val="masturbation"] { background: var(--primary); }
    .segment-opt.active[data-val="intercourse"] { background: var(--accent); }
    .input-row { display: flex; gap: 12px; margin-bottom: 12px; }
    .form-group { margin-bottom: 15px; flex: 1; }
    label { display: block; font-size: 0.8rem; color: #aaa; margin-bottom: 6px; }
    input, select, textarea { width: 100%; background: #222; border: 1px solid #333; color: #fff; padding: 12px; border-radius: 10px; font-size: 0.95rem; font-family: inherit; }
    .tag-group { display: flex; flex-wrap: wrap; gap: 8px; }
    .tag-cb input { display: none; }
    .tag-cb label { display: inline-block; padding: 6px 14px; background: rgba(255,255,255,0.05); border-radius: 20px; font-size: 0.8rem; color: #ccc; cursor: pointer; border: 1px solid transparent; transition: 0.2s; }
    .tag-cb input:checked + label { background: rgba(255,255,255,0.15); border-color: var(--primary); color: #fff; }
    .record-card { display: flex; align-items: center; padding: 16px; border-radius: 16px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); margin-bottom: 10px; transition: 0.2s; cursor: pointer; }
    .record-icon { width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; margin-right: 15px; background: rgba(0,0,0,0.3); flex-shrink: 0; }
    .user-avatar { width: 80px; height: 80px; border-radius: 50%; background-size: cover; background-position: center; background-color: #333; margin: 0 auto 15px; display: flex; align-items: center; justify-content: center; font-size: 2rem; border: 4px solid rgba(255,255,255,0.1); cursor:pointer; overflow: hidden; }
    .form-subtitle { font-size: 0.75rem; color: var(--secondary); margin: 15px 0 8px; font-weight: bold; border-left: 3px solid var(--secondary); padding-left: 8px; }
    
    /* Admin Table */
    .admin-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; color: #ccc; }
    .admin-table th { text-align: left; padding: 10px; color: #666; border-bottom: 1px solid #333; }
    .admin-table td { padding: 10px; border-bottom: 1px solid #222; }
  </style>
</head>
<body>
  <div class="ambient-bg"></div>

  <!-- 沉浸式计时器 -->
  <div id="immersiveTimer">
      <div class="pulse-ring"></div>
      <div style="color:#aaa; font-size:0.9rem; margin-bottom:10px; letter-spacing:2px;">沉浸时刻</div>
      <div id="imTimerDisplay" class="timer-display">00:00:00</div>
      <div class="timer-btn-stop" onclick="stopTimer()">⏹</div>
      <div style="margin-top:20px; color:#555; font-size:0.8rem;">专注当下，享受此刻</div>
  </div>

  <!-- 登录页 -->
  <div id="authScreen" style="position:fixed; top:0; left:0; width:100%; height:100%; z-index:1000; background:#050505; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:30px;">
    <h1 style="font-family:'Cinzel'; font-size:2.5rem; background:linear-gradient(to right, #fff, var(--primary)); -webkit-background-clip:text; -webkit-text-fill-color:transparent; margin-bottom:40px;">Secret Garden</h1>
    <div class="glass card" style="width:100%; max-width:320px;">
      <input type="text" id="lg-user" placeholder="用户名" style="margin-bottom:15px;">
      <input type="password" id="lg-pass" placeholder="密码" style="margin-bottom:20px;">
      <button class="btn" onclick="doLogin()">进入花园</button>
      <button class="btn btn-outline" style="margin-top:10px;" onclick="doRegister()">新用户注册</button>
      <div id="loginMsg" style="text-align:center; margin-top:15px; font-size:0.8rem; color:var(--accent);"></div>
    </div>
  </div>

  <div id="app" class="container hidden">
    <!-- 头部 -->
    <header style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
       <h2 style="font-family:'Cinzel'; margin:0; font-size:1.4rem;">My Garden</h2>
       <div style="display:flex; align-items:center; gap:10px;">
           <span id="headerDate" style="font-size:0.8rem; color:#666;"></span>
           <!-- 加号按钮 -->
           <button onclick="openModal(false)" style="background:rgba(255,255,255,0.1); border:none; color:var(--primary); width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:1.2rem;">+</button>
       </div>
    </header>

    <!-- 视图：首页 (Home) -->
    <div id="view-home">
       <div class="stats-grid">
         <div class="stat-box"><div class="stat-val" id="sTotal">0</div><div class="stat-label">总次数</div></div>
         <div class="stat-box"><div class="stat-val" id="sDuration">0</div><div class="stat-label">均时长 (分)</div></div>
         <div class="stat-box"><div class="stat-val" id="sScore">0</div><div class="stat-label">满意度</div></div>
         <div class="stat-box"><div class="stat-val" id="sOrgasm" style="color:var(--primary);">0</div><div class="stat-label">总高潮</div></div>
       </div>

       <!-- 优化后的图表容器 -->
       <div class="glass card charts-wrapper">
          <div class="chart-box-main"><canvas id="chartHistory"></canvas></div>
          <div class="chart-box-side"><canvas id="chartType"></canvas></div>
       </div>

       <div style="display:flex; gap:10px; margin-bottom:15px;">
          <input type="text" id="searchInput" placeholder="搜索..." style="flex:1;">
          <select id="statsRange" style="width:100px;" onchange="loadStats(this.value)">
             <option value="all">全部</option><option value="month">本月</option><option value="3_months">近3月</option><option value="year">今年</option>
          </select>
       </div>
       <div id="listContainer"></div>
       <div id="scrollSentinel" style="text-align:center; padding:20px; font-size:0.8rem; color:#555;">加载中...</div>
    </div>

    <!-- 视图：时光轨迹 (History) -->
    <div id="view-history" class="hidden">
       <h3 style="font-family:'Cinzel'; border-bottom:1px solid #333; padding-bottom:10px;">时光轨迹</h3>
       <div id="timelineContainer" class="timeline"></div>
       <div id="historySentinel" style="text-align:center; padding:10px; color:#555; font-size:0.8rem;">加载更多</div>
    </div>

    <!-- 视图：榜单 -->
    <div id="view-leaderboard" class="hidden">
       <h3 style="font-family:'Cinzel'; border-bottom:1px solid #333; padding-bottom:10px;">极乐名人堂</h3>
       <table style="width:100%; border-collapse:collapse; color:#ccc; font-size:0.9rem;">
          <thead><tr style="color:#666; font-size:0.8rem; text-align:left;"><th>#</th><th>玩家</th><th>时长</th><th>次数</th></tr></thead>
          <tbody id="leaderboardBody"></tbody>
       </table>
    </div>

    <!-- 视图：个人中心 -->
    <div id="view-profile" class="hidden">
       <div class="glass card" style="text-align:center; margin-top:20px;">
          <div class="user-avatar" id="avatarDisplay" onclick="toggleAvatarInput()">👤</div>
          <div id="avatarInputBox" class="hidden" style="margin-bottom:15px;">
             <input type="text" id="avatarUrlInput" placeholder="输入头像图片链接 (URL)" style="margin-bottom:5px;">
             <button class="btn btn-outline" style="padding:5px;" onclick="saveAvatar()">保存头像</button>
          </div>
          <h2 id="profileUser" style="margin:0 0 5px 0;">User</h2>
          <div style="font-size:0.8rem; color:#666;">秘密花园会员</div>
       </div>
       <div class="card" style="background:rgba(255,255,255,0.02);">
          <h4 style="margin:0 0 15px 0; border-bottom:1px solid #333; padding-bottom:10px;">安全设置</h4>
          <div class="form-group"><input type="password" id="p-old" placeholder="当前密码"></div>
          <div class="form-group"><input type="password" id="p-new" placeholder="新密码 (至少5位)"></div>
          <button class="btn btn-outline" onclick="changePassword()">修改密码</button>
       </div>
       
       <!-- 管理入口 -->
       <button class="btn btn-outline" style="border-style:dashed; color:#666; margin-top:10px;" onclick="switchView('admin', null)">管理后台</button>
       
       <button class="btn" style="background:#333; color:#aaa; margin-top:20px;" onclick="logout()">退出登录</button>
       <div style="text-align:center; margin-top:30px; font-size:0.7rem; color:#444;">v7.5 Admin Edition</div>
    </div>

    <!-- 视图：管理后台 -->
    <div id="view-admin" class="hidden">
        <h3 style="font-family:'Cinzel'; color:var(--accent);">Admin Dashboard</h3>
        
        <!-- 管理登录 -->
        <div id="adminLoginBox">
            <p style="font-size:0.8rem; color:#888;">请输入管理员密码进行验证</p>
            <div style="display:flex; gap:10px;">
                <input type="password" id="adminPassInput" placeholder="管理员密码" style="flex:1;">
                <button class="btn" style="width:80px;" onclick="verifyAdmin()">验证</button>
            </div>
        </div>

        <!-- 管理内容 -->
        <div id="adminContent" class="hidden">
            <div class="stats-grid">
                <div class="stat-box"><div class="stat-val" id="admUsers">0</div><div class="stat-label">注册用户</div></div>
                <div class="stat-box"><div class="stat-val" id="admRecords">0</div><div class="stat-label">总记录数</div></div>
            </div>
            <p style="font-size:0.7rem; text-align:center; color:#555;">DB Size Est: <span id="admDbSize">-</span></p>
            
            <h4 style="border-bottom:1px solid #333; padding-bottom:10px; margin-top:20px;">用户管理</h4>
            <div style="overflow-x:auto;">
                <table class="admin-table">
                    <thead><tr><th>用户</th><th>注册时间</th><th>记录数</th><th>操作</th></tr></thead>
                    <tbody id="adminUserList"></tbody>
                </table>
            </div>
        </div>
    </div>
  </div>

  <!-- 底部 Dock 导航 (优化版) -->
  <div class="dock-nav" id="dockNav">
    <div class="dock-item active" onclick="switchView('home', this)">
      <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
      <span>首页</span>
    </div>
    <div class="dock-item" onclick="switchView('history', this)">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
      <span>历史</span>
    </div>
    <!-- 计时器按钮 (融合设计) -->
    <div class="dock-item timer-btn" onclick="startTimer()">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12"></polyline><line x1="12" y1="6" x2="12" y2="2"></line></svg>
      <span>计时</span>
    </div>
    <div class="dock-item" onclick="switchView('leaderboard', this)">
      <svg viewBox="0 0 24 24"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"></path><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"></path><path d="M4 22h16"></path></svg>
      <span>榜单</span>
    </div>
    <div class="dock-item" onclick="switchView('profile', this)">
      <svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"></path><circle cx="12" cy="7" r="4"></circle></svg>
      <span>我的</span>
    </div>
  </div>

  <!-- 记录编辑器弹窗 -->
  <div id="modalOverlay" class="modal-overlay">
    <div class="modal-content">
       <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
          <h3 id="formTitle" style="margin:0;">记录</h3>
          <span onclick="closeModal()" style="font-size:1.5rem; color:#666; cursor:pointer;">&times;</span>
       </div>
       <input type="hidden" id="recordId">
       <div class="segment-control">
          <div class="segment-opt active" data-val="masturbation" onclick="setActType('masturbation')">🖐 独享 (自慰)</div>
          <div class="segment-opt" data-val="intercourse" onclick="setActType('intercourse')">❤️ 欢愉 (性爱)</div>
       </div>
       <input type="hidden" id="actType" value="masturbation">
       <div class="form-group"><label>时间</label><input type="datetime-local" id="datetime"></div>
       <div class="input-row">
          <div class="form-group"><label>地点</label><select id="location"><option value="bedroom">卧室</option><option value="living_room">客厅</option><option value="bathroom">浴室</option><option value="hotel">酒店</option><option value="car">车内</option><option value="outdoor">野战</option><option value="office">办公室</option><option value="other">其他</option></select></div>
          <div class="form-group"><label>心情</label><select id="mood"><option value="horny">🔥 性致勃勃</option><option value="lonely">🌑 孤独</option><option value="stressed">😫 压力释放</option><option value="bored">🥱 无聊</option><option value="drunk">🍷 微醺</option><option value="morning_wood">🌅 晨勃</option></select></div>
       </div>
       
       <div id="secMasturbation">
          <div class="form-subtitle">助兴素材</div>
          <div class="form-group"><select id="stimulation"><option value="none">纯想象</option><option value="porn_pov">第一人称 (POV)</option><option value="porn_amateur">素人/自拍</option><option value="porn_pro">专业AV</option><option value="hentai">二次元/里番</option><option value="erotica">色情文学</option><option value="audio">娇喘/ASMR</option><option value="cam">网聊/直播</option><option value="photos">写真套图</option></select></div>
          
          <div class="form-subtitle">玩法与技巧</div>
          <div class="tag-group">
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_hand" value="m_hand"><label for="m_hand">传统手艺</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_lube" value="m_lube"><label for="m_lube">大量润滑</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_edging" value="m_edging"><label for="m_edging">边缘控射(寸止)</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_fast" value="m_fast"><label for="m_fast">快速冲刺</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_slow" value="m_slow"><label for="m_slow">慢玩享受</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_prostate" value="m_prostate"><label for="m_prostate">前列腺</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="m_anal" value="m_anal"><label for="m_anal">后庭探索</label></div>
          </div>

          <div class="form-subtitle">辅助用具</div>
          <div class="tag-group">
                <div class="tag-cb"><input type="checkbox" name="acts" id="toy_cup" value="toy_cup"><label for="toy_cup">飞机杯</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="toy_vibe" value="toy_vibe"><label for="toy_vibe">震动棒</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="toy_milker" value="toy_milker"><label for="toy_milker">榨精机</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="toy_doll" value="toy_doll"><label for="toy_doll">实体娃娃</label></div>
          </div>
       </div>

       <div id="secIntercourse" class="hidden">
          <div class="input-row">
             <div class="form-group"><label>伴侣姓名</label><input type="text" id="partnerName" placeholder="姓名/昵称"></div>
             <div class="form-group"><label>体位</label><select id="sexualPosition"><option value="">--选择--</option><option value="missionary">传教士</option><option value="doggy">后入式</option><option value="cowgirl">女上位</option><option value="69">69式</option><option value="prone_bone">俯卧后入</option><option value="standing">站立式</option></select></div>
          </div>
          <div class="form-subtitle">行为细节</div>
             <div class="tag-group">
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_oral_give" value="oral_give"><label for="i_oral_give">口(攻)</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_oral_recv" value="oral_receive"><label for="i_oral_recv">口(受)</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_vag" value="vaginal"><label for="i_vag">阴道</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_anal" value="anal"><label for="i_anal">后庭</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_cream" value="creampie"><label for="i_cream">内射</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_fing" value="fingering"><label for="i_fing">指交</label></div>
                <div class="tag-cb"><input type="checkbox" name="acts" id="i_toy" value="toy_lube"><label for="i_toy">用具</label></div>
             </div>
       </div>

       <div style="background:#222; border-radius:12px; padding:15px; margin:20px 0 15px;">
          <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
             <span style="font-size:0.8rem; color:#aaa;">时长: <span id="vDur" style="color:#fff; font-size:1rem;">15</span> 分钟</span>
             <span style="font-size:0.8rem; color:#aaa;">满意度: <span id="vSat" style="color:#fff; font-size:1rem;">5</span></span>
          </div>
          <input type="range" id="duration" min="0" max="180" step="1" value="15" oninput="document.getElementById('vDur').innerText=this.value" style="margin-bottom:10px;">
          <input type="range" id="satisfaction" min="1" max="10" step="1" value="5" oninput="document.getElementById('vSat').innerText=this.value">
       </div>
       <div class="input-row">
          <div class="form-group"><label>高潮次数</label><input type="number" id="orgasmCount" value="1"></div>
          <div class="form-group"><label>射精次数</label><input type="number" id="ejaculationCount" value="1"></div>
       </div>
       <div class="form-group"><label>备注/日记</label><textarea id="experience" rows="3" placeholder="写下感受..."></textarea></div>
       <div style="height:20px;"></div>
       <div style="display:flex; gap:10px;">
         <button class="btn" style="height:50px; flex:1;" onclick="saveRecord()">保存记录</button>
         <button id="deleteBtn" class="btn" style="height:50px; width:80px; background:var(--accent); display:none;" onclick="deleteCurrentRecord()">删除</button>
       </div>
    </div>
  </div>

  <script>
    const API = '/api';
    const TR_MAP = ${JSON.stringify(TR_MAP)};
    function tr(k) { return TR_MAP[k] || k; }
    
    let token = localStorage.getItem('sg_token');
    let user = localStorage.getItem('sg_user');
    let adminPass = localStorage.getItem('sg_admin_pass');
    
    let currentPage = 1, isLoading = false, hasMore = true;
    let historyPage = 1, historyLoading = false, historyHasMore = true;
    let chart1, chart2;
    let timerInterval = null;

    (function() {
      if(token) {
        document.getElementById('authScreen').style.display='none';
        document.getElementById('app').classList.remove('hidden');
        document.getElementById('profileUser').innerText = user;
        const avatar = localStorage.getItem('sg_avatar_'+user);
        if(avatar) document.getElementById('avatarDisplay').style.backgroundImage = \`url('\${avatar}')\`;
        
        loadStats();
        setupInfiniteScroll();
        checkTimerState();
        let t; document.getElementById('searchInput').addEventListener('input', ()=>{ clearTimeout(t); t=setTimeout(()=>{resetList();loadRecords();},500); });
        
        // Auto check admin
        if(adminPass) {
             document.getElementById('adminPassInput').value = adminPass;
             document.getElementById('adminLoginBox').classList.add('hidden');
             document.getElementById('adminContent').classList.remove('hidden');
        }
      }
    })();

    function getHeaders() { 
        const h = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token };
        if(adminPass) h['X-Admin-Pass'] = adminPass;
        return h;
    }

    // Auth & Profile
    async function doLogin() {
       const u = document.getElementById('lg-user').value, p = document.getElementById('lg-pass').value;
       const r = await fetch(API+'/auth/login', { method:'POST', body:JSON.stringify({username:u, password:p}) });
       const d = await r.json();
       if(d.token) { localStorage.setItem('sg_token', d.token); localStorage.setItem('sg_user', d.username); location.reload(); }
       else document.getElementById('loginMsg').innerText = d.error || '登录失败';
    }
    async function doRegister() {
        const u = document.getElementById('lg-user').value, p = document.getElementById('lg-pass').value;
        const r = await fetch(API+'/auth/register', { method:'POST', body:JSON.stringify({username:u, password:p}) });
        const d = await r.json();
        document.getElementById('loginMsg').innerText = d.error || d.message;
    }
    function logout() { localStorage.clear(); location.reload(); }
    async function changePassword() {
        const o = document.getElementById('p-old').value, n = document.getElementById('p-new').value;
        const r = await fetch(API+'/auth/password', { method:'POST', headers:getHeaders(), body:JSON.stringify({oldPassword:o, newPassword:n}) });
        const d = await r.json(); alert(d.error || d.message);
    }
    function toggleAvatarInput() { document.getElementById('avatarInputBox').classList.toggle('hidden'); }
    function saveAvatar() {
        const url = document.getElementById('avatarUrlInput').value;
        if(url) {
            localStorage.setItem('sg_avatar_'+user, url);
            document.getElementById('avatarDisplay').style.backgroundImage = \`url('\${url}')\`;
            document.getElementById('avatarDisplay').innerText = '';
            toggleAvatarInput();
        }
    }

    // --- Admin Logic ---
    async function verifyAdmin() {
        const p = document.getElementById('adminPassInput').value;
        adminPass = p; // temporarily set for request
        const r = await fetch(API+'/api/admin/stats', { headers: getHeaders() });
        if(r.status === 200) {
            localStorage.setItem('sg_admin_pass', p);
            document.getElementById('adminLoginBox').classList.add('hidden');
            document.getElementById('adminContent').classList.remove('hidden');
            loadAdminData();
        } else {
            alert('验证失败');
            adminPass = null;
        }
    }
    async function loadAdminData() {
        const r1 = await fetch(API+'/admin/stats', { headers: getHeaders() });
        const s = await r1.json();
        document.getElementById('admUsers').innerText = s.users;
        document.getElementById('admRecords').innerText = s.records;
        document.getElementById('admDbSize').innerText = s.db_size_est;

        const r2 = await fetch(API+'/admin/users', { headers: getHeaders() });
        const users = await r2.json();
        const tbody = document.getElementById('adminUserList'); tbody.innerHTML = '';
        users.forEach(u => {
            const date = new Date(u.created_at).toLocaleDateString();
            tbody.insertAdjacentHTML('beforeend', \`<tr><td>\${u.username}</td><td>\${date}</td><td>\${u.rec_count}</td><td><button style="padding:4px 8px; background:#b91c1c; border:none; color:#fff; border-radius:4px; cursor:pointer;" onclick="deleteUser('\${u.uid}')">删除</button></td></tr>\`);
        });
    }
    async function deleteUser(uid) {
        if(!confirm('危险操作：确定要删除该用户及其所有记录吗？')) return;
        const r = await fetch(API+'/admin/users?uid='+uid, { method:'DELETE', headers: getHeaders() });
        if(r.status===200) loadAdminData(); else alert('Error');
    }

    // --- Stats & Home List ---
    async function loadStats(range='all') {
        const r = await fetch(API+'/statistics?range='+range, { headers: getHeaders() });
        const s = await r.json();
        if(s.error === 'Unauthorized') return logout();
        document.getElementById('sTotal').innerText = s.total_records;
        document.getElementById('sDuration').innerText = Math.round(s.avg_duration);
        document.getElementById('sScore').innerText = s.avg_satisfaction;
        document.getElementById('sOrgasm').innerText = s.total_orgasms;
        
        Chart.defaults.color = '#666'; Chart.defaults.responsive = true; Chart.defaults.maintainAspectRatio = false;
        if(chart1) chart1.destroy(); if(chart2) chart2.destroy();
        
        const ctx1 = document.getElementById('chartType').getContext('2d');
        chart1 = new Chart(ctx1, { type: 'doughnut', data: { labels: ['自慰','性爱'], datasets: [{ data: [s.masturbation, s.intercourse], backgroundColor: ['#d946ef', '#f43f5e'], borderWidth: 0 }] }, options: { maintainAspectRatio:false, cutout: '75%', plugins: { legend: { display: false } } } });
        
        const ctx2 = document.getElementById('chartHistory').getContext('2d');
        const labels = Object.keys(s.records_by_month).sort();
        chart2 = new Chart(ctx2, { type: 'bar', data: { labels: labels.map(l=>l.slice(5)), datasets: [{ label: '次', data: labels.map(k => s.records_by_month[k]), backgroundColor: '#8b5cf6', borderRadius: 4 }] }, options: { maintainAspectRatio:false, scales: { x: { grid: {display:false} }, y: { display:false } }, plugins: { legend: {display:false} } } });
        
        if(currentPage===1) loadRecords();
    }
    function resetList() { currentPage=1; hasMore=true; document.getElementById('listContainer').innerHTML=''; }
    async function loadRecords() {
        if(isLoading || !hasMore) return; isLoading = true;
        const q = document.getElementById('searchInput').value;
        const r = await fetch(\`\${API}/records?page=\${currentPage}&search=\${q}\`, { headers: getHeaders() });
        const d = await r.json();
        if(d.records.length === 0) { hasMore=false; document.getElementById('scrollSentinel').innerText = '—— 到底了 ——'; }
        else { d.records.forEach(renderItem); currentPage++; }
        isLoading = false;
    }
    function renderItem(item) {
        const isM = item.activity_type === 'masturbation';
        const d = new Date(item.datetime);
        const dateStr = \`\${d.getMonth()+1}/\${d.getDate()} \${d.getHours()}:\${d.getMinutes().toString().padStart(2,'0')}\`;
        let tags = []; if(item.mood) tags.push(tr(item.mood)); if(isM && item.stimulation) tags.push(tr(item.stimulation));
        const html = \`<div class="record-card \${isM?'type-m':'type-i'}" onclick="editRecord('\${item.id}')"><div class="record-icon">\${isM ? '🖐' : '❤️'}</div><div style="flex:1;"><div style="display:flex; justify-content:space-between; color:#eee; font-weight:600; margin-bottom:4px;"><span>\${tr(item.location||'unknown')}</span><span style="color:\${isM?'var(--primary)':'var(--accent)'}">\${item.duration}分</span></div><div style="font-size:0.8rem; color:#888;">\${dateStr} · \${item.satisfaction}/10</div><div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">\${tags.map(t=>\`<span style="background:rgba(255,255,255,0.1); padding:2px 6px; border-radius:4px; font-size:0.7rem;">\${t}</span>\`).join('')}</div></div></div>\`;
        document.getElementById('listContainer').insertAdjacentHTML('beforeend', html);
    }

    // --- History Logic ---
    async function loadHistory() {
        if(historyLoading || !historyHasMore) return; historyLoading = true;
        const r = await fetch(\`\${API}/records?page=\${historyPage}\`, { headers: getHeaders() });
        const d = await r.json();
        const c = document.getElementById('timelineContainer');
        if(d.records.length === 0) { historyHasMore=false; document.getElementById('historySentinel').innerText = '一切的开始'; }
        else {
            d.records.forEach(item => {
                const isM = item.activity_type === 'masturbation';
                const d = new Date(item.datetime);
                const timeStr = \`\${d.getFullYear()}-\${d.getMonth()+1}-\${d.getDate()} \${d.getHours()}:\${d.getMinutes().toString().padStart(2,'0')}\`;
                const html = \`<div class="timeline-item"><div class="timeline-dot" style="border-color:\${isM?'var(--primary)':'var(--accent)'}"></div><div class="timeline-date">\${timeStr}</div><div class="timeline-content" onclick="editRecord('\${item.id}')"><div style="display:flex; justify-content:space-between; margin-bottom:5px;"><strong style="color:#fff">\${isM?'独享':'欢愉'} · \${tr(item.location)}</strong><span>\${item.duration} 分钟</span></div><div style="font-size:0.85rem; color:#aaa;">\${item.experience || '无备注...'}</div></div></div>\`;
                c.insertAdjacentHTML('beforeend', html);
            });
            historyPage++;
        }
        historyLoading = false;
    }
    
    // --- Timer ---
    function checkTimerState() {
        const start = localStorage.getItem('timerStart');
        if(start) { showTimerOverlay(parseInt(start)); }
    }
    function startTimer() {
        const now = Date.now();
        localStorage.setItem('timerStart', now);
        showTimerOverlay(now);
    }
    function showTimerOverlay(startTime) {
        document.getElementById('immersiveTimer').style.display = 'flex';
        if(timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            const diff = Date.now() - startTime;
            const h=Math.floor(diff/3600000), m=Math.floor((diff%3600000)/60000), s=Math.floor((diff%60000)/1000);
            document.getElementById('imTimerDisplay').innerText = \`\${h.toString().padStart(2,'0')}:\${m.toString().padStart(2,'0')}:\${s.toString().padStart(2,'0')}\`;
        }, 1000);
    }
    function stopTimer() {
        const start = localStorage.getItem('timerStart');
        if(start) {
            const diff = Date.now() - parseInt(start);
            const min = Math.max(1, Math.round(diff/60000));
            localStorage.removeItem('timerStart');
            clearInterval(timerInterval);
            document.getElementById('immersiveTimer').style.display = 'none';
            openModal(false);
            document.getElementById('duration').value = min;
            document.getElementById('vDur').innerText = min;
        }
    }

    // --- Forms ---
    function setActType(type) {
        document.getElementById('actType').value = type;
        document.querySelectorAll('.segment-opt').forEach(el => el.classList.toggle('active', el.dataset.val === type));
        document.getElementById('secMasturbation').classList.toggle('hidden', type !== 'masturbation');
        document.getElementById('secIntercourse').classList.toggle('hidden', type !== 'intercourse');
    }
    function openModal(isEdit) {
        document.getElementById('modalOverlay').style.display = 'flex';
        document.getElementById('formTitle').innerText = isEdit ? '编辑' : '新记录';
        document.getElementById('deleteBtn').style.display = isEdit ? 'block' : 'none';
        if(!isEdit) {
            document.getElementById('recordId').value = '';
            const now = new Date(); now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
            document.getElementById('datetime').value = now.toISOString().slice(0,16);
            setActType('masturbation');
            document.getElementById('duration').value = 15; document.getElementById('vDur').innerText = 15;
            document.getElementById('satisfaction').value = 5; document.getElementById('vSat').innerText = 5;
            document.getElementById('orgasmCount').value = 1; document.querySelectorAll('input[type="checkbox"]').forEach(c => c.checked = false);
            document.getElementById('partnerName').value = ''; document.getElementById('sexualPosition').value = ''; document.getElementById('experience').value = '';
        }
    }
    function closeModal() { document.getElementById('modalOverlay').style.display='none'; }
    async function editRecord(id) {
        const r = await fetch(API+'/records/detail?id='+id, { headers: getHeaders() });
        const d = await r.json();
        openModal(true);
        document.getElementById('recordId').value = d.id;
        setActType(d.activity_type);
        const utc = new Date(d.datetime);
        const loc = new Date(utc.getTime() - (utc.getTimezoneOffset() * 60000));
        document.getElementById('datetime').value = loc.toISOString().slice(0,16);
        ['location','mood','duration','satisfaction','orgasmCount','ejaculationCount','experience'].forEach(k => {
             const key = k === 'orgasmCount' ? 'orgasm_count' : (k === 'ejaculationCount' ? 'ejaculation_count' : k);
             if(d[key] !== undefined) document.getElementById(k).value = d[key];
        });
        document.getElementById('vDur').innerText = d.duration; document.getElementById('vSat').innerText = d.satisfaction;
        if(d.stimulation) document.getElementById('stimulation').value = d.stimulation;
        if(d.partner_name) document.getElementById('partnerName').value = d.partner_name;
        if(d.sexual_position) document.getElementById('sexualPosition').value = d.sexual_position;
        const acts = d.acts || [];
        document.querySelectorAll('input[name="acts"]').forEach(cb => cb.checked = acts.includes(cb.value));
    }
    async function saveRecord() {
        const id = document.getElementById('recordId').value;
        const type = document.getElementById('actType').value;
        const acts = [];
        document.querySelectorAll('input[name="acts"]:checked').forEach(c => acts.push(c.value));
        const data = {
          id: id||undefined, activity_type: type, datetime: new Date(document.getElementById('datetime').value).toISOString(),
          duration: document.getElementById('duration').value, location: document.getElementById('location').value, mood: document.getElementById('mood').value,
          satisfaction: document.getElementById('satisfaction').value, orgasm_count: document.getElementById('orgasmCount').value, ejaculation_count: document.getElementById('ejaculationCount').value,
          experience: document.getElementById('experience').value, acts: acts,
          stimulation: type==='masturbation' ? document.getElementById('stimulation').value : undefined,
          partner_name: type==='intercourse' ? document.getElementById('partnerName').value : undefined,
          sexual_position: type==='intercourse' ? document.getElementById('sexualPosition').value : undefined
       };
       await fetch(API+'/records', { method:id?'PUT':'POST', headers: getHeaders(), body:JSON.stringify(data) });
       closeModal(); resetList(); loadRecords(); loadStats(); 
       if(!document.getElementById('view-history').classList.contains('hidden')) { 
           historyPage=1; document.getElementById('timelineContainer').innerHTML=''; historyHasMore=true; loadHistory();
       }
    }
    async function deleteCurrentRecord() {
       const id = document.getElementById('recordId').value;
       if(!id || !confirm('确定要删除这条记录吗？此操作不可撤销。')) return;
       const r = await fetch(API+'/records?id='+id, { method:'DELETE', headers: getHeaders() });
       const d = await r.json();
       if(d.error) { alert('删除失败: '+d.error); return; }
       alert('删除成功');
       closeModal(); resetList(); loadRecords(); loadStats();
       if(!document.getElementById('view-history').classList.contains('hidden')) {
           historyPage=1; document.getElementById('timelineContainer').innerHTML=''; historyHasMore=true; loadHistory();
       }
    }

    // --- Nav ---
    function switchView(v, el) {
        document.querySelectorAll('.dock-item').forEach(d => d.classList.remove('active'));
        if(el) el.classList.add('active');
        ['home','leaderboard','profile','history','admin'].forEach(name => {
           const div = document.getElementById('view-'+name);
           if(name === v) { div.classList.remove('hidden'); div.style.animation='slideUp 0.3s'; }
           else div.classList.add('hidden');
        });
        if(v==='leaderboard') loadLeaderboard();
        if(v==='history' && document.getElementById('timelineContainer').innerHTML==='') loadHistory();
        if(v==='admin' && adminPass) loadAdminData();
    }
    async function loadLeaderboard() {
        const r = await fetch(API+'/leaderboard', { headers: getHeaders() });
        const list = await r.json();
        const b = document.getElementById('leaderboardBody'); b.innerHTML = '';
        list.forEach((i, idx) => { b.insertAdjacentHTML('beforeend', \`<tr style="border-bottom:1px solid #222"><td style="padding:12px; color:\${idx<3?'var(--primary)':'#666'}">\${idx+1}</td><td>\${i.username}</td><td>\${Math.round(i.total_duration/60)}h</td><td>\${i.total_records}</td></tr>\`); });
    }
    function setupInfiniteScroll() { 
        const obs = new IntersectionObserver(e=>{if(e[0].isIntersecting) loadRecords()}); obs.observe(document.getElementById('scrollSentinel'));
        const obsH = new IntersectionObserver(e=>{if(e[0].isIntersecting) loadHistory()}); obsH.observe(document.getElementById('historySentinel'));
    }
  </script>
</body>
</html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}