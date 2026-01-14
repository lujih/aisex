/**
 * 秘密花园 (Secret Garden) - v7.0 Remastered
 * 数据库: Cloudflare D1 (绑定变量: DB)
 */

const DEFAULT_JWT_SECRET = 'change-this-secret-in-env-vars-please'; 
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

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
      if (path === '/api/auth/register') return await registerUser(request, env);
      if (path === '/api/auth/login') return await loginUser(request, env);
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

// --- 后端逻辑 (保持不变，省略部分重复代码以节省空间，功能与原来一致) ---
async function getRecords(req, env, user) {
  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20; const offset = (page - 1) * limit;
  const search = (url.searchParams.get('search') || '').trim();
  let sql = `SELECT * FROM records WHERE uid = ?`; let params = [user.uid];
  if (search) { sql += ` AND (data_json LIKE ? OR location LIKE ? OR mood LIKE ?)`; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  sql += ` ORDER BY datetime DESC LIMIT ? OFFSET ?`; params.push(limit, offset);
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  const records = results.map(r => { let extra = {}; try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {} return { ...r, ...extra, data_json: undefined }; });
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
  const data = await req.json(); const id = generateId();
  const { core, extra } = splitData(data, user.uid, id);
  await env.DB.prepare(`INSERT INTO records (id, uid, activity_type, datetime, duration, location, mood, satisfaction, orgasm_count, ejaculation_count, data_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(core.id, core.uid, core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra), new Date().toISOString()).run();
  return jsonResponse({ message: 'Created', id });
}
async function updateRecord(req, env, user) {
  const data = await req.json(); if (!data.id) return errorResponse('Missing ID');
  const existing = await env.DB.prepare('SELECT id FROM records WHERE id = ? AND uid = ?').bind(data.id, user.uid).first();
  if (!existing) return errorResponse('Forbidden', 403);
  const { core, extra } = splitData(data, user.uid, data.id);
  await env.DB.prepare(`UPDATE records SET activity_type = ?, datetime = ?, duration = ?, location = ?, mood = ?, satisfaction = ?, orgasm_count = ?, ejaculation_count = ?, data_json = ? WHERE id = ? AND uid = ?`).bind(core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, core.orgasm_count, core.ejaculation_count, JSON.stringify(extra), core.id, core.uid).run();
  return jsonResponse({ message: 'Updated' });
}
async function deleteRecord(url, env, user) {
  const id = url.searchParams.get('id'); await env.DB.prepare('DELETE FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).run(); return jsonResponse({ message: 'Deleted' });
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
  const records_by_month = {}; if(monthRes.results) [...monthRes.results].reverse().forEach(row => records_by_month[row.month] = row.count);
  return jsonResponse({ total_records: stats.total_records || 0, masturbation: stats.masturbation || 0, intercourse: stats.intercourse || 0, total_orgasms: stats.total_orgasms || 0, avg_satisfaction: parseFloat((stats.avg_satisfaction || 0).toFixed(1)), avg_duration: Math.round(stats.avg_duration || 0), records_by_month });
}
async function getLeaderboard(env) {
    const { results } = await env.DB.prepare(`SELECT u.username, count(r.id) as total_records, sum(r.duration) as total_duration, sum(case when r.activity_type = 'masturbation' then 1 else 0 end) as masturbation_count FROM records r JOIN users u ON r.uid = u.uid GROUP BY u.uid ORDER BY total_duration DESC LIMIT 50`).all();
    return jsonResponse(results);
}
async function registerUser(req, env) {
  const { username, password } = await req.json(); if (!username || !password || username.length < 3) return errorResponse('Invalid params');
  try { await env.DB.prepare('INSERT INTO users (uid, username, password_hash) VALUES (?, ?, ?)').bind(generateId(), username, await hashPassword(password)).run(); return jsonResponse({ message: 'OK' }); } catch (e) { return errorResponse('Exists'); }
}
async function loginUser(req, env) {
  const { username, password } = await req.json();
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  if (!user || (await hashPassword(password)) !== user.password_hash) return errorResponse('Auth Failed', 401);
  const token = await signJwt({ uid: user.uid, username: user.username }, env.JWT_SECRET || DEFAULT_JWT_SECRET); return jsonResponse({ token, username });
}
async function changePassword(req, env, user) {
  const { oldPassword, newPassword } = await req.json();
  const dbUser = await env.DB.prepare('SELECT password_hash FROM users WHERE uid = ?').bind(user.uid).first();
  if((await hashPassword(oldPassword)) !== dbUser.password_hash) return errorResponse('Old password wrong', 403);
  await env.DB.prepare('UPDATE users SET password_hash = ? WHERE uid = ?').bind(await hashPassword(newPassword), user.uid).run(); return jsonResponse({ message: 'OK' });
}
function splitData(data, uid, id) {
    const coreMap = ['activity_type','datetime','duration','location','mood','satisfaction','orgasm_count','ejaculation_count'];
    const core = { uid, id, duration:0, satisfaction:0, orgasm_count:0, ejaculation_count:0 }; const extra = {};
    for (let k in data) { if (coreMap.includes(k)) core[k] = data[k]; else if (k !== 'id' && k !== 'uid' && k !== 'created_at') extra[k] = data[k]; }
    ['duration','satisfaction','orgasm_count','ejaculation_count'].forEach(k => core[k] = parseInt(core[k]) || 0); return { core, extra };
}
async function hashPassword(pw) { const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pw)); return [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join(''); }
async function verifyAuth(request, env) { const h = request.headers.get('Authorization'); if (!h || !h.startsWith('Bearer ')) return null; try { return await verifyJwt(h.split(' ')[1], env.JWT_SECRET || DEFAULT_JWT_SECRET); } catch (e) { return null; } }
async function signJwt(payload, secret) { const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })); const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+604800 })); const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`)); return `${header}.${body}.${b64url(sig)}`; }
async function verifyJwt(token, secret) { const [h, b, s] = token.split('.'); const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']); if (!await crypto.subtle.verify('HMAC', key, b64urlDecode(s), new TextEncoder().encode(`${h}.${b}`))) throw new Error('Invalid'); const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(b))); if (payload.exp < Date.now()/1000) throw new Error('Expired'); return payload; }
function b64url(s) { return (typeof s==='string'?btoa(s):btoa(String.fromCharCode(...new Uint8Array(s)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(s) { return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }
function jsonResponse(data, status = 200) { return new Response(JSON.stringify(data), { status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }); }
function errorResponse(msg, status = 400) { return jsonResponse({ error: msg }, status); }
function generateId() { return Date.now().toString(36) + Math.random().toString(36).substring(2, 6); }

// ==========================================
// 前端 HTML (重构版)
// ==========================================
async function serveFrontend() {
  const html = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
  <meta name="theme-color" content="#0f0c15">
  <title>Secret Garden | 秘密花园</title>
  <link href="https://fonts.googleapis.com/css2?family=Montserrat:wght@300;400;600&family=Cinzel:wght@400;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {
      --bg-deep: #050505;
      --primary: #d946ef; /* Fuchsia 500 */
      --primary-dark: #a21caf;
      --secondary: #8b5cf6; /* Violet 500 */
      --accent: #f43f5e; /* Rose 500 */
      --glass-surface: rgba(30, 30, 35, 0.6);
      --glass-border: rgba(255, 255, 255, 0.08);
      --glass-shine: rgba(255, 255, 255, 0.03);
      --text-main: #f3f4f6;
      --text-muted: #9ca3af;
    }
    
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
    body {
      margin: 0; padding: 0;
      background-color: var(--bg-deep);
      color: var(--text-main);
      font-family: 'Montserrat', sans-serif;
      min-height: 100vh;
      overflow-x: hidden;
      padding-bottom: 90px; /* Space for bottom nav */
    }

    /* 动态背景 */
    .ambient-bg {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2;
      background: radial-gradient(circle at 10% 20%, #1a0b2e 0%, transparent 40%),
                  radial-gradient(circle at 90% 80%, #2e0b1f 0%, transparent 40%),
                  linear-gradient(to bottom, #0a0a0a, #050505);
      animation: bgPulse 15s ease-in-out infinite alternate;
    }
    @keyframes bgPulse { 0% { opacity: 0.8; } 100% { opacity: 1; transform: scale(1.05); } }

    /* 通用工具类 */
    .font-serif { font-family: 'Cinzel', serif; }
    .text-gradient { background: linear-gradient(135deg, #fff 0%, #e879f9 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .glass {
      background: var(--glass-surface);
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border: 1px solid var(--glass-border);
      box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
    }
    .card { border-radius: 20px; padding: 20px; transition: transform 0.2s, box-shadow 0.2s; position: relative; overflow: hidden; }
    .card::before { content:''; position: absolute; top:0; left:0; right:0; height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); }
    
    /* 按钮 */
    .btn {
      background: linear-gradient(135deg, var(--primary), var(--secondary));
      color: white; border: none; border-radius: 12px;
      padding: 12px 20px; font-weight: 600; font-size: 0.95rem;
      cursor: pointer; position: relative; overflow: hidden;
      box-shadow: 0 4px 15px rgba(217, 70, 239, 0.3);
      transition: all 0.3s ease;
    }
    .btn:active { transform: scale(0.97); }
    .btn-outline { background: transparent; border: 1px solid rgba(255,255,255,0.2); color: var(--text-main); box-shadow: none; }
    .btn-icon { width: 40px; height: 40px; border-radius: 50%; display: flex; align-items: center; justify-content: center; padding: 0; font-size: 1.2rem; }

    /* 布局 */
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px; padding-top: 10px; }
    .hidden { display: none !important; }
    
    /* 底部导航 Dock */
    .dock-nav {
      position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%);
      width: 90%; max-width: 400px; height: 65px;
      background: rgba(20, 20, 25, 0.85);
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 35px;
      display: flex; justify-content: space-around; align-items: center;
      z-index: 100; box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    .dock-item {
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      color: #6b7280; font-size: 0.7rem; gap: 4px; transition: 0.3s; cursor: pointer;
    }
    .dock-item svg { width: 24px; height: 24px; fill: currentColor; transition: 0.3s; }
    .dock-item.active { color: var(--primary); }
    .dock-item.active svg { transform: translateY(-3px); filter: drop-shadow(0 4px 8px rgba(217, 70, 239, 0.4)); }
    .dock-fab {
      width: 50px; height: 50px; background: var(--primary); border-radius: 50%;
      display: flex; align-items: center; justify-content: center;
      margin-top: -30px; border: 4px solid var(--bg-deep);
      box-shadow: 0 0 15px var(--primary); color: #fff; font-size: 1.5rem;
    }

    /* 统计卡片 */
    .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin-bottom: 25px; }
    .stat-box { background: rgba(255,255,255,0.03); padding: 15px; border-radius: 16px; text-align: center; border: 1px solid rgba(255,255,255,0.05); }
    .stat-val { font-family: 'Cinzel', serif; font-size: 1.8rem; background: linear-gradient(to right, #fff, #e2e8f0); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .stat-label { font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 5px; }

    /* 列表 */
    .record-list { display: flex; flex-direction: column; gap: 12px; padding-bottom: 80px; }
    .record-card {
      display: flex; align-items: center; padding: 16px; border-radius: 18px;
      background: linear-gradient(145deg, rgba(255,255,255,0.03) 0%, rgba(255,255,255,0.01) 100%);
      border: 1px solid rgba(255,255,255,0.05); cursor: pointer;
    }
    .record-icon {
      width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem;
      background: rgba(0,0,0,0.3); margin-right: 15px; flex-shrink: 0;
    }
    .type-m .record-icon { color: var(--secondary); box-shadow: inset 0 0 10px rgba(139, 92, 246, 0.2); }
    .type-i .record-icon { color: var(--accent); box-shadow: inset 0 0 10px rgba(244, 63, 94, 0.2); }
    .record-info { flex: 1; }
    .record-main { font-weight: 600; font-size: 1rem; color: #eee; display: flex; justify-content: space-between; }
    .record-meta { font-size: 0.8rem; color: #888; margin-top: 4px; display: flex; align-items: center; gap: 8px; }
    .pill { font-size: 0.7rem; padding: 2px 8px; border-radius: 10px; background: rgba(255,255,255,0.1); color: #ccc; }
    
    /* 表单模态框 */
    .modal-overlay {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 200;
      background: rgba(0,0,0,0.6); backdrop-filter: blur(8px);
      display: none; align-items: flex-end; justify-content: center;
      animation: fadeIn 0.3s ease;
    }
    .modal-content {
      width: 100%; max-width: 600px; background: #16161a;
      border-radius: 24px 24px 0 0; padding: 25px;
      max-height: 90vh; overflow-y: auto;
      border-top: 1px solid rgba(255,255,255,0.1);
      box-shadow: 0 -10px 40px rgba(0,0,0,0.5);
      animation: slideUp 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }
    @keyframes slideUp { from { transform: translateY(100%); } to { transform: translateY(0); } }
    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

    /* 自定义表单控件 */
    .form-group { margin-bottom: 18px; }
    .form-label { display: block; font-size: 0.85rem; color: #aaa; margin-bottom: 8px; font-weight: 500; }
    .custom-input, .custom-select, textarea {
      width: 100%; background: #0a0a0c; border: 1px solid #333; color: #fff;
      padding: 12px 15px; border-radius: 12px; font-size: 1rem; transition: 0.2s; font-family: inherit;
    }
    .custom-input:focus, .custom-select:focus, textarea:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(217, 70, 239, 0.15); }
    
    .range-slider { -webkit-appearance: none; width: 100%; height: 6px; background: #333; border-radius: 5px; outline: none; }
    .range-slider::-webkit-slider-thumb { -webkit-appearance: none; width: 20px; height: 20px; background: var(--primary); border-radius: 50%; cursor: pointer; box-shadow: 0 0 10px var(--primary); }

    /* 复选框网格 */
    .tag-grid { display: flex; flex-wrap: wrap; gap: 8px; }
    .check-tag input { display: none; }
    .check-tag label {
      display: inline-block; padding: 8px 16px; background: rgba(255,255,255,0.05);
      border-radius: 20px; font-size: 0.85rem; color: #ccc; cursor: pointer;
      border: 1px solid transparent; transition: 0.2s;
    }
    .check-tag input:checked + label { background: rgba(217, 70, 239, 0.2); border-color: var(--primary); color: #fff; text-shadow: 0 0 8px var(--primary); }

    /* 登录页 */
    .auth-container {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 1000;
      background: radial-gradient(circle at center, #1a1a20 0%, #000 100%);
      display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 30px;
    }
    .logo-text { font-family: 'Cinzel', serif; font-size: 2.5rem; margin-bottom: 40px; background: linear-gradient(to right, #fff, #d946ef); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }

    /* 计时器浮窗 */
    .timer-overlay {
      position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.9); z-index: 300;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .timer-display { font-size: 4rem; font-family: 'Montserrat', monospace; font-weight: 200; color: #fff; text-shadow: 0 0 20px var(--primary); margin: 20px 0; }

    /* 加载动画 */
    .spinner { width: 30px; height: 30px; border: 3px solid rgba(255,255,255,0.1); border-top-color: var(--primary); border-radius: 50%; animation: spin 0.8s linear infinite; margin: 20px auto; }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="ambient-bg"></div>

  <!-- 登录界面 -->
  <div id="authScreen" class="auth-container">
    <div class="logo-text">Secret Garden</div>
    <div class="glass card" style="width:100%; max-width:350px;">
      <div class="form-group"><input type="text" id="lg-user" class="custom-input" placeholder="用户名"></div>
      <div class="form-group"><input type="password" id="lg-pass" class="custom-input" placeholder="密码"></div>
      <button class="btn" style="width:100%; margin-top:10px;" onclick="doLogin()">进入花园</button>
      <button class="btn btn-outline" style="width:100%; margin-top:10px;" onclick="doRegister()">创建账户</button>
      <div id="loginMsg" style="text-align:center; color: var(--accent); margin-top:15px; font-size:0.8rem;"></div>
    </div>
  </div>

  <!-- 主应用 -->
  <div id="app" class="container hidden" style="opacity:0; transition: opacity 0.5s;">
    <!-- 头部 -->
    <header class="header">
      <div>
        <h1 class="font-serif text-gradient" style="margin:0; font-size:1.5rem;">My Garden</h1>
        <div style="font-size:0.8rem; color:var(--text-muted);">欢迎回来, <span id="welcomeUser" style="color:#fff;"></span></div>
      </div>
      <button class="btn btn-icon btn-outline" onclick="logout()" style="width:36px; height:36px;">
        <svg style="width:18px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
      </button>
    </header>

    <!-- 视图：统计/首页 -->
    <div id="view-home">
      <!-- 统计概览 -->
      <div class="stats-grid">
        <div class="stat-box glass">
          <div class="stat-val" id="sTotal">0</div>
          <div class="stat-label">总次数</div>
        </div>
        <div class="stat-box glass">
          <div class="stat-val" id="sDuration">0<span style="font-size:0.9rem">m</span></div>
          <div class="stat-label">平均时长</div>
        </div>
      </div>
      
      <!-- 图表区域 -->
      <div class="glass card" style="margin-bottom:20px; height:220px; display:flex; gap:10px;">
        <div style="flex:1; position:relative;"><canvas id="chartHistory"></canvas></div>
        <div style="width:100px; position:relative;"><canvas id="chartType"></canvas></div>
      </div>

      <!-- 筛选与搜索 -->
      <div style="display:flex; gap:10px; margin-bottom:15px;">
        <input type="text" id="searchInput" class="custom-input" style="padding:10px 15px; height:44px;" placeholder="🔍 搜索记忆...">
        <select id="timeRange" class="custom-select" style="width:100px; height:44px;" onchange="loadStats(this.value)">
          <option value="all">全部</option>
          <option value="month">本月</option>
          <option value="3_months">近3月</option>
        </select>
      </div>

      <div id="listContainer" class="record-list"></div>
      <div id="scrollSentinel" style="text-align:center; color:#666; font-size:0.8rem; padding:10px;"></div>
    </div>

    <!-- 视图：排行榜 -->
    <div id="view-leaderboard" class="hidden">
      <h2 class="font-serif" style="margin-bottom:20px;">Hall of Pleasure</h2>
      <div class="glass card" style="padding:0;">
        <table style="width:100%; text-align:left; border-collapse:collapse; color:#ddd;">
          <thead style="background:rgba(255,255,255,0.05); font-size:0.8rem; color:#888;">
            <tr><th style="padding:15px;">#</th><th>玩家</th><th>时长</th><th>次数</th></tr>
          </thead>
          <tbody id="leaderboardBody" style="font-size:0.9rem;"></tbody>
        </table>
      </div>
    </div>
    
    <!-- 视图：设置 (简单版) -->
    <div id="view-settings" class="hidden">
       <h2 class="font-serif">设置</h2>
       <div class="glass card">
         <div class="form-group">
           <label class="form-label">修改密码</label>
           <input type="password" id="pwd-old" class="custom-input" placeholder="旧密码" style="margin-bottom:10px;">
           <input type="password" id="pwd-new" class="custom-input" placeholder="新密码" style="margin-bottom:10px;">
           <button class="btn btn-outline" style="width:100%" onclick="changePassword()">更新密码</button>
         </div>
       </div>
    </div>

    <!-- 底部 Dock -->
    <div class="dock-nav">
      <div class="dock-item active" onclick="switchView('home', this)">
        <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
        <span>首页</span>
      </div>
      <div class="dock-fab" onclick="openModal(false)">
        <svg viewBox="0 0 24 24" style="width:28px;height:28px;"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
      </div>
      <div class="dock-item" onclick="switchView('leaderboard', this)">
        <svg viewBox="0 0 24 24"><path d="M6 9H4.5a2.5 2.5 0 0 1 0-5H6"></path><path d="M18 9h1.5a2.5 2.5 0 0 0 0-5H18"></path><path d="M4 22h16"></path><path d="M10 14.66V17c0 .55-.47.98-.97 1.21C7.85 18.75 7 20.24 7 22"></path><path d="M14 14.66V17c0 .55.47.98.97 1.21C16.15 18.75 17 20.24 17 22"></path><path d="M18 2H6v7a6 6 0 0 0 12 0V2Z"></path></svg>
        <span>榜单</span>
      </div>
    </div>
  </div>
  
  <!-- 全屏计时器界面 -->
  <div id="timerOverlay" class="timer-overlay hidden">
     <div style="color:var(--text-muted); letter-spacing:2px; font-size:0.9rem;">SESSION IN PROGRESS</div>
     <div id="timerBigDisplay" class="timer-display">00:00:00</div>
     <button class="btn" style="width:160px; height:50px; border-radius:25px; font-size:1.1rem; box-shadow:0 0 20px rgba(217,70,239,0.5);" onclick="stopTimer()">完成</button>
     <div style="margin-top:20px; font-size:0.8rem; color:#555;">保持专注，享受此刻</div>
  </div>

  <!-- 编辑/新建 模态框 -->
  <div id="modalOverlay" class="modal-overlay">
    <div class="modal-content glass">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:20px;">
        <h3 id="formTitle" style="margin:0;">记录美好</h3>
        <span onclick="closeModal()" style="font-size:1.5rem; cursor:pointer;">&times;</span>
      </div>
      <input type="hidden" id="recordId">
      
      <!-- 类型切换 -->
      <div style="display:flex; gap:10px; margin-bottom:20px;">
         <label class="check-tag" style="flex:1; text-align:center;">
            <input type="radio" name="actType" value="masturbation" checked onchange="toggleFormType()">
            <label style="width:100%; border-radius:12px;">🖐 独享 (自慰)</label>
         </label>
         <label class="check-tag" style="flex:1; text-align:center;">
            <input type="radio" name="actType" value="intercourse" onchange="toggleFormType()">
            <label style="width:100%; border-radius:12px;">❤️ 欢愉 (性爱)</label>
         </label>
      </div>

      <div class="form-group">
        <label class="form-label">时间</label>
        <input type="datetime-local" id="datetime" class="custom-input">
      </div>

      <div style="display:flex; gap:15px;">
        <div class="form-group" style="flex:1;">
           <label class="form-label">地点</label>
           <select id="location" class="custom-select">
             <option value="bedroom">卧室</option><option value="living_room">客厅</option><option value="bathroom">浴室</option><option value="hotel">酒店</option><option value="car">车内</option><option value="outdoor">野战</option><option value="office">办公室</option><option value="other">其他</option>
           </select>
        </div>
        <div class="form-group" style="flex:1;">
           <label class="form-label">心情</label>
           <select id="mood" class="custom-select">
             <option value="horny">🔥 性致勃勃</option><option value="lonely">🌑 孤独</option><option value="stressed">😫 压力释放</option><option value="bored">🥱 无聊</option><option value="drunk">🍷 微醺</option><option value="morning_wood">🌅 晨勃</option>
           </select>
        </div>
      </div>

      <!-- 独享特定 -->
      <div id="secMasturbation">
        <div class="form-group">
          <label class="form-label">助兴素材</label>
          <select id="stimulation" class="custom-select">
            <option value="none">纯想象</option><option value="porn_pov">POV视角</option><option value="porn_amateur">素人/自拍</option><option value="hentai">二次元</option><option value="erotica">色情文学</option><option value="audio">娇喘/ASMR</option><option value="toy_lube">需要很多润滑油</option>
          </select>
        </div>
        <div class="form-group">
          <label class="form-label">玩法</label>
          <div class="tag-grid">
             <div class="check-tag"><input type="checkbox" name="acts" id="m_hand" value="m_hand"><label for="m_hand">手冲</label></div>
             <div class="check-tag"><input type="checkbox" name="acts" id="m_edging" value="m_edging"><label for="m_edging">边缘控射</label></div>
             <div class="check-tag"><input type="checkbox" name="acts" id="toy_cup" value="toy_cup"><label for="toy_cup">飞机杯</label></div>
             <div class="check-tag"><input type="checkbox" name="acts" id="m_prostate" value="m_prostate"><label for="m_prostate">前列腺</label></div>
          </div>
        </div>
      </div>

      <!-- 欢愉特定 -->
      <div id="secIntercourse" class="hidden">
        <div class="form-group"><label class="form-label">伴侣</label><input type="text" id="partnerName" class="custom-input" placeholder="名字..."></div>
        <div class="form-group"><label class="form-label">体位</label><select id="sexualPosition" class="custom-select"><option value="">未记录</option><option value="missionary">传教士</option><option value="doggy">后入式</option><option value="cowgirl">女上位</option><option value="69">69式</option></select></div>
        <div class="form-group">
          <label class="form-label">行为</label>
          <div class="tag-grid">
             <div class="check-tag"><input type="checkbox" name="acts" id="act_oral" value="oral_give"><label for="act_oral">口爱</label></div>
             <div class="check-tag"><input type="checkbox" name="acts" id="act_vag" value="vaginal"><label for="act_vag">阴道交</label></div>
             <div class="check-tag"><input type="checkbox" name="acts" id="act_creampie" value="creampie"><label for="act_creampie">内射</label></div>
          </div>
        </div>
      </div>

      <!-- 滑动条区域 -->
      <div class="glass" style="border-radius:12px; padding:15px; margin-bottom:15px;">
        <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
           <span style="font-size:0.85rem; color:#ccc;">持续时长</span>
           <span style="font-weight:bold; color:var(--primary);"><span id="vDur">15</span> 分钟</span>
        </div>
        <input type="range" id="duration" class="range-slider" min="0" max="120" value="15" oninput="document.getElementById('vDur').innerText=this.value">
        
        <div style="display:flex; justify-content:space-between; margin-top:15px; margin-bottom:5px;">
           <span style="font-size:0.85rem; color:#ccc;">满意度</span>
           <span style="font-weight:bold; color:var(--secondary);"><span id="vSat">5</span> / 10</span>
        </div>
        <input type="range" id="satisfaction" class="range-slider" min="1" max="10" value="5" oninput="document.getElementById('vSat').innerText=this.value" style="background:#4c1d95">
      </div>

      <div style="display:flex; gap:15px; margin-bottom:15px;">
         <div style="flex:1"><label class="form-label">高潮次数</label><input type="number" id="orgasmCount" class="custom-input" value="1"></div>
         <div style="flex:1"><label class="form-label">射精次数</label><input type="number" id="ejaculationCount" class="custom-input" value="1"></div>
      </div>

      <div class="form-group">
        <label class="form-label">体验备注</label>
        <textarea id="experience" rows="3" placeholder="记录下当时的感受..."></textarea>
      </div>

      <button class="btn" style="width:100%; margin-top:10px; height:50px; font-size:1rem;" onclick="saveRecord()">保存记录</button>
      <div style="height:60px;"></div> <!-- 底部垫高 -->
    </div>
  </div>

  <div id="globalTimerBtn" onclick="toggleGlobalTimer()" style="position:fixed; bottom:100px; right:20px; width:50px; height:50px; border-radius:50%; background:#222; border:1px solid #444; display:flex; align-items:center; justify-content:center; box-shadow:0 5px 15px rgba(0,0,0,0.5); z-index:90;">⏱️</div>

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
      if(token) {
        document.getElementById('authScreen').style.display='none';
        document.getElementById('app').classList.remove('hidden');
        setTimeout(()=>document.getElementById('app').style.opacity=1, 50);
        document.getElementById('welcomeUser').innerText = user;
        loadStats();
        setupInfiniteScroll();
        checkTimerState();
      }
      
      // 搜索防抖
      let timeout;
      document.getElementById('searchInput').addEventListener('input', (e) => {
         clearTimeout(timeout);
         timeout = setTimeout(() => { resetList(); loadRecords(); }, 500);
      });
    })();

    function getHeaders() { return { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token }; }

    // --- 认证 ---
    async function doLogin() {
       const u = document.getElementById('lg-user').value;
       const p = document.getElementById('lg-pass').value;
       if(!u || !p) return showLoginMsg('请输入账号密码');
       try {
         const r = await fetch(API+'/auth/login', { method:'POST', body:JSON.stringify({username:u, password:p}) });
         const d = await r.json();
         if(d.token) {
             localStorage.setItem('sg_token', d.token); localStorage.setItem('sg_user', d.username);
             location.reload();
         } else showLoginMsg(d.error || '登录失败');
       } catch(e){ showLoginMsg('网络错误'); }
    }
    async function doRegister() {
        const u = document.getElementById('lg-user').value;
        const p = document.getElementById('lg-pass').value;
        if(!u || !p) return showLoginMsg('请输入账号密码');
        const r = await fetch(API+'/auth/register', { method:'POST', body:JSON.stringify({username:u, password:p}) });
        const d = await r.json();
        if(d.error) showLoginMsg(d.error); else showLoginMsg('注册成功，请登录');
    }
    function showLoginMsg(msg) { document.getElementById('loginMsg').innerText = msg; }
    function logout() { localStorage.clear(); location.reload(); }
    async function changePassword() {
        const o = document.getElementById('pwd-old').value, n = document.getElementById('pwd-new').value;
        const r = await fetch(API+'/auth/password', { method:'POST', headers:getHeaders(), body:JSON.stringify({oldPassword:o, newPassword:n}) });
        const d = await r.json(); alert(d.error || d.message);
    }

    // --- 核心业务 ---
    async function loadStats(range='all') {
        const r = await fetch(API+'/statistics?range='+range, { headers: getHeaders() });
        const s = await r.json();
        if(s.error === 'Unauthorized') return logout();
        
        document.getElementById('sTotal').innerText = s.total_records;
        document.getElementById('sDuration').innerHTML = Math.round(s.avg_duration) + '<span style="font-size:0.9rem;margin-left:2px;">m</span>';
        
        // 渲染图表
        Chart.defaults.color = '#888';
        if(chart1) chart1.destroy();
        if(chart2) chart2.destroy();
        
        // 环形图
        const ctx1 = document.getElementById('chartType').getContext('2d');
        chart1 = new Chart(ctx1, {
            type: 'doughnut',
            data: { labels: ['自慰','性爱'], datasets: [{ data: [s.masturbation, s.intercourse], backgroundColor: ['#d946ef', '#f43f5e'], borderWidth: 0 }] },
            options: { maintainAspectRatio:false, cutout: '70%', plugins: { legend: { display: false } } }
        });

        // 柱状图
        const ctx2 = document.getElementById('chartHistory').getContext('2d');
        const labels = Object.keys(s.records_by_month).sort();
        const data = labels.map(k => s.records_by_month[k]);
        
        // 创建渐变
        const gradient = ctx2.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, '#8b5cf6'); gradient.addColorStop(1, 'rgba(139, 92, 246, 0.1)');

        chart2 = new Chart(ctx2, {
            type: 'bar',
            data: { labels: labels.map(l=>l.slice(5)), datasets: [{ label: '次数', data: data, backgroundColor: gradient, borderRadius: 4, barThickness: 12 }] },
            options: { maintainAspectRatio:false, scales: { x: { grid: {display:false} }, y: { display:false } }, plugins: { legend: {display:false} } }
        });
        
        // 初始加载列表
        if(currentPage===1) loadRecords();
    }

    function resetList() { currentPage=1; hasMore=true; document.getElementById('listContainer').innerHTML=''; }
    async function loadRecords() {
        if(isLoading || !hasMore) return;
        isLoading = true;
        document.getElementById('scrollSentinel').innerHTML = '<div class="spinner"></div>';
        
        const q = document.getElementById('searchInput').value;
        const r = await fetch(\`\${API}/records?page=\${currentPage}&search=\${q}\`, { headers: getHeaders() });
        const d = await r.json();
        
        if(d.records.length === 0) {
            hasMore = false;
            document.getElementById('scrollSentinel').innerText = '—— 到底了 ——';
        } else {
            d.records.forEach(renderItem);
            currentPage++;
            document.getElementById('scrollSentinel').innerText = '下滑加载更多';
        }
        isLoading = false;
    }

    function renderItem(item) {
        const isM = item.activity_type === 'masturbation';
        const date = new Date(item.datetime);
        const dateStr = \`\${date.getMonth()+1}/\${date.getDate()} \${date.getHours().toString().padStart(2,'0')}:\${date.getMinutes().toString().padStart(2,'0')}\`;
        
        let pills = [];
        if(item.mood) pills.push(tr(item.mood));
        if(isM && item.stimulation!=='none') pills.push(tr(item.stimulation));
        
        const html = \`
        <div class="record-card \${isM?'type-m':'type-i'}" onclick="editRecord('\${item.id}')">
            <div class="record-icon">\${isM ? '🖐' : '❤️'}</div>
            <div class="record-info">
                <div class="record-main">
                   <span>\${tr(item.location || 'unknown')}</span>
                   <span style="font-family:'Cinzel'; color:var(--primary); font-weight:bold;">\${item.duration}'</span>
                </div>
                <div class="record-meta">
                   <span>\${dateStr}</span>
                   \${pills.map(p=>\`<span class="pill">\${p}</span>\`).join('')}
                </div>
            </div>
        </div>\`;
        document.getElementById('listContainer').insertAdjacentHTML('beforeend', html);
    }

    // --- 表单逻辑 ---
    function toggleFormType() {
        const type = document.querySelector('input[name="actType"]:checked').value;
        const isM = type === 'masturbation';
        document.getElementById('secMasturbation').classList.toggle('hidden', !isM);
        document.getElementById('secIntercourse').classList.toggle('hidden', isM);
    }

    function openModal(isEdit, defaultDuration) {
        document.getElementById('modalOverlay').style.display = 'flex';
        document.getElementById('formTitle').innerText = isEdit ? '编辑记忆' : '新的篇章';
        
        if(!isEdit) {
            document.getElementById('recordId').value = '';
            // 设置当前本地时间
            const now = new Date();
            now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
            document.getElementById('datetime').value = now.toISOString().slice(0,16);
            document.getElementById('duration').value = defaultDuration || 15;
            document.getElementById('vDur').innerText = defaultDuration || 15;
            // 重置复选框
            document.querySelectorAll('input[type="checkbox"]').forEach(c=>c.checked=false);
            document.querySelector('input[name="actType"][value="masturbation"]').checked = true;
            toggleFormType();
        }
    }
    
    function closeModal() { document.getElementById('modalOverlay').style.display='none'; }

    async function editRecord(id) {
        const r = await fetch(API+'/records/detail?id='+id, { headers: getHeaders() });
        const d = await r.json();
        openModal(true);
        
        document.getElementById('recordId').value = d.id;
        document.querySelector(\`input[name="actType"][value="\${d.activity_type}"]\`).checked = true;
        toggleFormType();
        
        // UTC -> Local input
        const utcDate = new Date(d.datetime);
        const localDate = new Date(utcDate.getTime() - (utcDate.getTimezoneOffset() * 60000));
        document.getElementById('datetime').value = localDate.toISOString().slice(0,16);
        
        ['location','mood','stimulation','partnerName','sexualPosition','experience'].forEach(k => {
             if(document.getElementById(k)) document.getElementById(k).value = d[k]||'';
        });
        ['duration','satisfaction','orgasmCount','ejaculationCount'].forEach(k => {
             const v = d[k]||0; document.getElementById(k).value = v;
        });
        document.getElementById('vDur').innerText = d.duration;
        document.getElementById('vSat').innerText = d.satisfaction;

        // Checkboxes
        const acts = d.acts || [];
        document.querySelectorAll('input[name="acts"]').forEach(cb => { cb.checked = acts.includes(cb.value); });
    }

    async function saveRecord() {
        const id = document.getElementById('recordId').value;
        const type = document.querySelector('input[name="actType"]:checked').value;
        const acts = [];
        document.querySelectorAll('input[name="acts"]:checked').forEach(c => acts.push(c.value));
        
        const localVal = document.getElementById('datetime').value;
        
        const data = {
          id: id||undefined,
          activity_type: type,
          datetime: new Date(localVal).toISOString(),
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
       await fetch(API+'/records', { method:id?'PUT':'POST', headers: getHeaders(), body:JSON.stringify(data) });
       closeModal();
       resetList(); loadRecords(); loadStats();
    }

    // --- 视图切换 ---
    function switchView(viewName, el) {
        document.querySelectorAll('.dock-item').forEach(d => d.classList.remove('active'));
        if(el) el.classList.add('active');
        
        ['home','leaderboard','settings'].forEach(v => {
            const div = document.getElementById('view-'+v);
            if(v === viewName) { div.classList.remove('hidden'); div.style.animation='fadeIn 0.4s'; }
            else div.classList.add('hidden');
        });
        
        if(viewName === 'leaderboard') loadLeaderboard();
    }
    
    async function loadLeaderboard() {
        const r = await fetch(API+'/leaderboard', { headers: getHeaders() });
        const list = await r.json();
        const b = document.getElementById('leaderboardBody'); b.innerHTML = '';
        list.forEach((i, idx) => {
            b.insertAdjacentHTML('beforeend', \`
            <tr style="border-bottom:1px solid rgba(255,255,255,0.05)">
                <td style="padding:12px 15px; color:\${idx<3?'var(--primary)':'#666'}">\${idx+1}</td>
                <td>\${i.username}</td>
                <td>\${Math.round(i.total_duration/60)}h</td>
                <td>\${i.total_records}</td>
            </tr>\`);
        });
    }

    // --- 计时器 ---
    function checkTimerState() {
        const start = localStorage.getItem('timerStart');
        if(start) { showTimerOverlay(parseInt(start)); }
    }
    function toggleGlobalTimer() {
        const start = localStorage.getItem('timerStart');
        if(start) { 
            // 如果已经在计时，这里可以作为一个快速入口回到计时界面
            showTimerOverlay(parseInt(start));
        } else {
            const now = Date.now();
            localStorage.setItem('timerStart', now);
            showTimerOverlay(now);
        }
    }
    function showTimerOverlay(startTime) {
        document.getElementById('timerOverlay').classList.remove('hidden');
        if(timerInterval) clearInterval(timerInterval);
        timerInterval = setInterval(() => {
            const diff = Date.now() - startTime;
            const h = Math.floor(diff/3600000).toString().padStart(2,'0');
            const m = Math.floor((diff%3600000)/60000).toString().padStart(2,'0');
            const s = Math.floor((diff%60000)/1000).toString().padStart(2,'0');
            document.getElementById('timerBigDisplay').innerText = \`\${h}:\${m}:\${s}\`;
        }, 1000);
    }
    function stopTimer() {
        const start = parseInt(localStorage.getItem('timerStart'));
        const duration = Math.max(1, Math.round((Date.now() - start)/60000));
        localStorage.removeItem('timerStart');
        clearInterval(timerInterval);
        document.getElementById('timerOverlay').classList.add('hidden');
        openModal(false, duration);
    }
    function setupInfiniteScroll() {
        const obs = new IntersectionObserver(es => { if(es[0].isIntersecting) loadRecords(); });
        obs.observe(document.getElementById('scrollSentinel'));
    }
  </script>
</body>
</html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}