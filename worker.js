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

// --- 日志辅助函数 ---
const generateReqId = () => crypto.randomUUID().split('-')[0];
const log = (reqId, level, msg, meta = {}) => {
    // 简化日志输出，生产环境可只保留 console.log(JSON.stringify(...))
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
    console.log(`[${new Date().toISOString()}] [${reqId}] [${level}] ${msg} ${metaStr}`);
};

// 优化：使用 UUID 替代 Math.random
function generateId() { return crypto.randomUUID().split('-')[0]; } // 使用短 UUID 或完整 UUID

export default {
  async fetch(request, env, ctx) {
    // 1. 初始化请求上下文
    const reqId = generateReqId();
    const startTime = Date.now();
    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = request.headers.get('cf-connecting-ip') || 'unknown';
    const method = request.method;

    // 2. 记录请求入口 (忽略 OPTIONS)
    if (method !== 'OPTIONS') { 
        log(reqId, 'INFO', `Incoming Request: ${method} ${path}`, { ip: clientIP });
    }

    // 3. CORS 预检
    if (method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });

    let response;
    try {
      // ============================
      // A. 公开/静态资源
      // ============================
      if (path === '/' || path === '/index.html') {
          response = await serveFrontend();
      }
      
      // ============================
      // B. 管理员接口 (Header 验证)
      // ============================
      else if (path.startsWith('/api/admin')) {
          log(reqId, 'WARN', `Admin Access Attempt`, { path }); 
          response = await handleAdmin(request, env, reqId);
      }

      // ============================
      // C. 公开认证接口
      // ============================
      else if (path === '/api/auth/register') {
          response = await registerUser(request, env, reqId);
      }
      else if (path === '/api/auth/login') {
          response = await loginUser(request, env, reqId);
      }

      // ============================
      // D. 用户受保护接口 (需要 JWT)
      // ============================
      else {
          // 统一鉴权
          const user = await verifyAuth(request, env);
          
          if (!user) {
              log(reqId, 'WARN', `Unauthorized Access`, { path, ip: clientIP });
              response = errorResponse('Unauthorized', 401);
          } else {
              // 记录用户操作
              if (method !== 'GET') {
                  log(reqId, 'INFO', `User Action: ${user.username}`, { method, path });
              }

              // --- 路由表 ---

              // 1. 核心记录 (CRUD)
              if (path === '/api/records') {
                  if (method === 'GET') response = await getRecords(request, env, user);
                  else if (method === 'POST') response = await createRecord(request, env, user);
                  else if (method === 'PUT') response = await updateRecord(request, env, user);
                  else if (method === 'DELETE') response = await deleteRecord(url, env, user);
              }
              else if (path === '/api/records/detail') {
                  response = await getRecordDetail(url, env, user);
              }
              else if (path === '/api/records/batch') {
                  // 批量操作
                  if (method === 'DELETE') response = await batchDeleteRecords(request, env, user);
                  else response = errorResponse('Method Not Allowed', 405);
              }

              // 2. 统计与分析
              else if (path === '/api/statistics') {
                  response = await getStatistics(request, env, user, ctx);
              }
              else if (path === '/api/statistics/details') {
                  // [新增] 标签云与伴侣统计
                  response = await getDetailedStatistics(request, env, user, ctx);
              }
              else if (path === '/api/leaderboard') {
                  response = await getLeaderboard(env);
              }

              // 3. 生理周期 (Health) - [修复 404 问题关键点]
              else if (path === '/api/cycles') {
                  if (method === 'GET') response = await getCycles(request, env, user);
                  else if (method === 'POST') response = await addCycle(request, env, user);
                  else if (method === 'DELETE') response = await deleteCycle(url, env, user);
              }
              else if (path === '/api/analysis/cycle-trends') {
                  response = await getCycleTrends(request, env, user);
              }

              // 4. 可视化 (Galaxy) - [修复 404 问题关键点]
              else if (path === '/api/visualization/galaxy') {
                  response = await getGalaxyData(request, env, user);
              }

              // 5. 工具/搜索/设置
              else if (path === '/api/search/suggest') {
                  response = await getSearchSuggestions(url, env, user);
              }
              else if (path === '/api/auth/password') {
                  response = await changePassword(request, env, user);
              }
              
              // 6. 404 Fallback
              else {
                  response = new Response('Not found', { status: 404, headers: CORS_HEADERS });
              }
          }
      }
    } catch (error) {
        log(reqId, 'ERROR', `Unhandled Exception`, { error: error.message, stack: error.stack });
        response = errorResponse('Internal Server Error', 500);
    } finally {
        if (method !== 'OPTIONS' && response) {
            const duration = Date.now() - startTime;
            // 避免日志过于频繁
            if (path !== '/api/records' || method !== 'GET') {
                 log(reqId, 'INFO', `Request Completed`, { status: response.status, duration: `${duration}ms` });
            }
        }
    }
    
    return response || new Response('Not found', { status: 404, headers: CORS_HEADERS });
  }
};

// --- 后端逻辑 ---
async function handleAdmin(req, env, reqId) {
    if (!env.ADMIN_PASSWORD) return errorResponse('Config Error', 500);
    if (req.headers.get('X-Admin-Pass') !== env.ADMIN_PASSWORD) {
        return errorResponse('Password Error', 403);
    }

    const url = new URL(req.url);
    const path = url.pathname;

    // 统计概览
    if (path === '/api/admin/stats') {
        const [uRes, rRes] = await Promise.all([
            env.DB.prepare('SELECT count(*) as c FROM users').first(),
            env.DB.prepare('SELECT count(*) as c FROM records').first()
        ]);
        return jsonResponse({ 
            users: uRes.c, 
            records: rRes.c, 
            db_size_est: (rRes.c * 0.5).toFixed(2) + ' KB' 
        });
    }

    // 用户列表与操作
    if (path === '/api/admin/users') {
        if (req.method === 'GET') {
            // [修改] 增加 last_login_attempt 字段查询
            const { results } = await env.DB.prepare(`
                SELECT uid, username, created_at, last_login_attempt, 
                (SELECT count(*) FROM records WHERE records.uid = users.uid) as rec_count 
                FROM users ORDER BY rec_count DESC
            `).all();
            return jsonResponse(results);
        }
        
        // 删除用户
        if (req.method === 'DELETE') {
            const uid = url.searchParams.get('uid');
            if (!uid) return errorResponse('Missing UID');
            await env.DB.batch([
                env.DB.prepare('DELETE FROM records WHERE uid = ?').bind(uid),
                env.DB.prepare('DELETE FROM users WHERE uid = ?').bind(uid)
            ]);
            return jsonResponse({ message: 'User deleted' });
        }
    }
    
    // [新增] 重置用户密码
    if (path === '/api/admin/users/reset') {
        if (req.method === 'POST') {
            const { uid, newPassword } = await req.json();
            if(!uid || !newPassword) return errorResponse('Missing params');
            
            const salt = generateSalt();
            const hash = await hashPassword(newPassword, salt);
            
            await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE uid = ?')
                .bind(hash, salt, new Date().toISOString(), uid)
                .run();
                
            return jsonResponse({ message: 'Password reset success' });
        }
    }
    
    return errorResponse('Not found', 404);
}

// 优化：使用 FTS5 全文搜索进行联合查询
async function getRecords(req, env, user) {
  const url = new URL(req.url);
  const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
  const limit = 20; 
  const offset = (page - 1) * limit;
  const search = (url.searchParams.get('search') || '').trim();
  
  let sql, params;

  if (search) {
      // --- FTS5 安全搜索逻辑 ---
      // 1. 移除双引号防止语法错误
      // 2. 将输入拆分为单词
      // 3. 过滤空字符串
      // 4. 为每个单词添加双引号和前缀通配符 (*)，构造 "AND" 查询
      const terms = search.replace(/"/g, '')
                          .split(/\s+/)
                          .filter(t => t.length > 0)
                          .map(w => `"${w}"*`);
      
      if (terms.length === 0) {
          // 如果清理后无有效关键词，回退到普通列表
          sql = `SELECT * FROM records WHERE uid = ? ORDER BY datetime DESC LIMIT ? OFFSET ?`;
          params = [user.uid, limit, offset];
      } else {
          // 构造 MATCH 查询字符串，例如: "bed"* AND "happy"*
          const safeSearch = terms.join(' AND ');
          
          sql = `
            SELECT r.* 
            FROM records r
            JOIN records_fts f ON r.id = f.record_id
            WHERE r.uid = ? 
            AND records_fts MATCH ?
            ORDER BY r.datetime DESC 
            LIMIT ? OFFSET ?
          `;
          params = [user.uid, safeSearch, limit, offset];
      }
  } else {
      // --- 普通浏览模式 ---
      // 强制 uid 检查，利用 idx_records_uid_datetime 索引
      sql = `SELECT * FROM records WHERE uid = ? ORDER BY datetime DESC LIMIT ? OFFSET ?`;
      params = [user.uid, limit, offset];
  }

  try {
      const { results } = await env.DB.prepare(sql).bind(...params).all();
      
      // 数据处理：解析 JSON 并展平到对象中
      const records = results.map(r => { 
          let extra = {}; 
          try { 
              extra = JSON.parse(r.data_json || '{}'); 
          } catch(e) {
              // 忽略损坏的 JSON，防止接口崩溃
          } 
          return { ...r, ...extra, data_json: undefined }; 
      });
      
      return jsonResponse({ records, page });
  } catch (e) {
      // 记录 FTS 错误（可能是数据库未迁移导致表不存在）
      console.error("Search/DB Error:", e);
      // 返回空列表而不是 500 错误，保证前端不白屏
      return jsonResponse({ records: [], page, error: "Query failed" });
  }
}
async function getRecordDetail(url, env, user) {
    const id = url.searchParams.get('id');
    
    // 并行查询主表和标签表
    const [r, actsRes] = await Promise.all([
        env.DB.prepare('SELECT * FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).first(),
        env.DB.prepare('SELECT act_type FROM record_acts WHERE record_id = ?').bind(id).all()
    ]);

    if (!r) return errorResponse('记录不存在', 404);

    let extra = {}; 
    try { extra = JSON.parse(r.data_json || '{}'); } catch(e) {}
    
    // 提取标签数组
    const acts = actsRes.results ? actsRes.results.map(row => row.act_type) : [];

    return jsonResponse({ 
        ...r, 
        ...extra, 
        data_json: undefined,
        acts: acts // 返回给前端
    });
}
function extractActs(data) {
    const acts = Array.isArray(data.acts) ? data.acts : [];
    // 确保 acts 不会被写入 data_json，节省空间
    if (data.acts) delete data.acts; 
    return acts;
}
async function createRecord(req, env, user) {
  const data = await req.json();
  const id = generateId(); // 确保 generateId 已定义
  const acts = extractActs(data); // 提取标签数组
  const { core, extra } = splitData(data, user.uid, id);
  
  // 1. 构建主表插入语句
  const mainStmt = env.DB.prepare(`
    INSERT INTO records (id, uid, activity_type, datetime, duration, location, mood, satisfaction, orgasm_count, ejaculation_count, partner_name, sexual_position, stimulation, data_json, created_at) 
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    core.id, core.uid, core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, core.orgasm_count, core.ejaculation_count, 
    extra.partner_name || null, extra.sexual_position || null, extra.stimulation || null, // 显式提取常用字段
    JSON.stringify(extra), new Date().toISOString()
  );

  // 2. 构建标签插入语句
  const actStmts = acts.map(act => 
      env.DB.prepare('INSERT INTO record_acts (record_id, act_type) VALUES (?, ?)').bind(id, act)
  );

  // 3. 批量执行
  await env.DB.batch([mainStmt, ...actStmts]);
  
  return jsonResponse({ message: '创建成功', id });
}
async function updateRecord(req, env, user) {
  const data = await req.json();
  if (!data.id) return errorResponse('缺少ID');
  
  const existing = await env.DB.prepare('SELECT id FROM records WHERE id = ? AND uid = ?').bind(data.id, user.uid).first();
  if (!existing) return errorResponse('无权修改', 403);

  const acts = extractActs(data);
  const { core, extra } = splitData(data, user.uid, data.id);

  // 1. 构建主表更新语句
  const updateStmt = env.DB.prepare(`
    UPDATE records SET 
      activity_type = ?, datetime = ?, duration = ?, location = ?, mood = ?, satisfaction = ?, 
      orgasm_count = ?, ejaculation_count = ?, partner_name = ?, sexual_position = ?, stimulation = ?, data_json = ? 
    WHERE id = ? AND uid = ?
  `).bind(
    core.activity_type, core.datetime, core.duration, core.location, core.mood, core.satisfaction, 
    core.orgasm_count, core.ejaculation_count, extra.partner_name || null, extra.sexual_position || null, extra.stimulation || null, JSON.stringify(extra), 
    core.id, core.uid
  );

  // 2. 标签更新策略：先删后加 (最稳妥的方式)
  const deleteActsStmt = env.DB.prepare('DELETE FROM record_acts WHERE record_id = ?').bind(core.id);
  const insertActsStmts = acts.map(act => 
      env.DB.prepare('INSERT INTO record_acts (record_id, act_type) VALUES (?, ?)').bind(core.id, act)
  );

  // 3. 批量执行
  await env.DB.batch([updateStmt, deleteActsStmt, ...insertActsStmts]);

  return jsonResponse({ message: '更新成功' });
}
async function deleteRecord(url, env, user) {
  const id = url.searchParams.get('id');
  await env.DB.prepare('DELETE FROM records WHERE id = ? AND uid = ?').bind(id, user.uid).run();
  return jsonResponse({ message: '删除成功' });
}
async function getStatistics(req, env, user, ctx) {
  const cacheUrl = new URL(req.url);
  const cacheKey = new Request(cacheUrl.toString(), req);
  const cache = caches.default;
  let response = await cache.match(cacheKey);
  if (response) return response;

  const url = new URL(req.url);
  const range = url.searchParams.get('range') || 'all';
  let timeFilter = '';
  if (range === 'month') timeFilter = " AND datetime >= datetime('now', 'start of month')";
  else if (range === 'year') timeFilter = " AND datetime >= datetime('now', '-1 year')";
  else if (range === '3_months') timeFilter = " AND datetime >= datetime('now', '-3 months')";

  // 基础统计
  const sqlBase = `SELECT 
      count(*) as total_records, 
      sum(case when activity_type = 'masturbation' then 1 else 0 end) as masturbation, 
      sum(case when activity_type = 'intercourse' then 1 else 0 end) as intercourse, 
      sum(orgasm_count) as total_orgasms, 
      avg(satisfaction) as avg_satisfaction, 
      avg(duration) as avg_duration 
      FROM records WHERE uid = ? ${timeFilter}`;
  
  // 月度趋势
  const monthSql = `SELECT strftime('%Y-%m', datetime) as month, count(*) as count FROM records WHERE uid = ? ${timeFilter} GROUP BY month ORDER BY month DESC LIMIT 12`;
  
  // 时段分布
  const hourSql = `SELECT strftime('%H', datetime) as hour, count(*) as count FROM records WHERE uid = ? ${timeFilter} GROUP BY hour`;

  // [新增] 热力图数据 (过去365天的每日数据)
  const dailySql = `SELECT date(datetime) as day, count(*) as count FROM records WHERE uid = ? AND datetime >= date('now', '-1 year') GROUP BY day`;

  const [stats, monthRes, hourRes, dailyRes] = await Promise.all([
      env.DB.prepare(sqlBase).bind(user.uid).first(),
      env.DB.prepare(monthSql).bind(user.uid).all(),
      env.DB.prepare(hourSql).bind(user.uid).all(),
      env.DB.prepare(dailySql).bind(user.uid).all() // 新增
  ]);

  const records_by_month = {};
  if(monthRes.results) [...monthRes.results].reverse().forEach(row => records_by_month[row.month] = row.count);

  const hour_distribution = new Array(24).fill(0);
  if(hourRes.results) hourRes.results.forEach(row => hour_distribution[parseInt(row.hour)] = row.count);

  // [新增] 处理热力图数据
  const daily_activity = {};
  if(dailyRes.results) dailyRes.results.forEach(row => daily_activity[row.day] = row.count);

  const data = {
    total_records: stats.total_records || 0,
    masturbation: stats.masturbation || 0,
    intercourse: stats.intercourse || 0,
    total_orgasms: stats.total_orgasms || 0,
    avg_satisfaction: parseFloat((stats.avg_satisfaction || 0).toFixed(1)),
    avg_duration: Math.round(stats.avg_duration || 0),
    records_by_month,
    hour_distribution,
    daily_activity // 返回给前端
  };

  response = jsonResponse(data);
  response.headers.set('Cache-Control', 'public, max-age=60');
  ctx.waitUntil(cache.put(cacheKey, response.clone()));
  return response;
}
// [新增] 智能搜索建议
async function getSearchSuggestions(url, env, user) {
    const q = (url.searchParams.get('q') || '').trim();
    if (q.length < 1) return jsonResponse([]);

    // 使用 FTS5 前缀查询获取匹配项，限制返回 5 条
    // 这里我们查询虚拟表，获取包含关键词的记录，并尝试提取上下文（简化版：只返回匹配的完整记录内容摘要）
    // 为了性能，这里我们也可以选择只查询 distinct location/mood 等，但 FTS 更强大
    const sql = `
        SELECT snippet(records_fts, 0, '<b>', '</b>', '...', 5) as match_text
        FROM records_fts 
        WHERE uid = ? AND records_fts MATCH ? 
        LIMIT 5
    `;
    // 构造前缀查询 "keyword*"
    const searchTerms = `"${q}"*`; 
    
    try {
        const { results } = await env.DB.prepare(sql).bind(user.uid, searchTerms).all();
        // 提取纯文本建议 (简化处理，实际可以更复杂)
        const suggestions = results.map(r => r.match_text.replace(/<[^>]+>/g, ''));
        return jsonResponse(suggestions);
    } catch (e) {
        return jsonResponse([]);
    }
}
async function getLeaderboard(env) {
    const { results } = await env.DB.prepare(`SELECT u.username, count(r.id) as total_records, sum(r.duration) as total_duration FROM records r JOIN users u ON r.uid = u.uid GROUP BY u.uid ORDER BY total_duration DESC LIMIT 50`).all();
    return jsonResponse(results);
}
async function registerUser(req, env, reqId) {
  const { username, password } = await req.json();
  if (!username || !password || username.length < 3) return errorResponse('无效参数');
  
  try { 
      const uid = generateId();
      const salt = generateSalt(); // 生成唯一盐
      const hash = await hashPassword(password, salt); // 带盐哈希

      await env.DB.prepare('INSERT INTO users (uid, username, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)')
        .bind(uid, username, hash, salt, new Date().toISOString())
        .run(); 
      
      log(reqId, 'INFO', `New User Registered`, { username, uid });
      return jsonResponse({ message: '注册成功' }); 
  } catch (e) { 
      log(reqId, 'WARN', `Registration Failed`, { username, error: e.message });
      return errorResponse('用户名已存在'); 
  }
}
async function loginUser(req, env, reqId) {
  if (!env.JWT_SECRET) return errorResponse('Config Error', 500);

  const { username, password } = await req.json();
  const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
  
  if (!user) return errorResponse('用户或密码错误', 401); // 模糊错误信息

  // 兼容性处理：如果老用户没有 salt (即 salt 为空字符串)，你需要决定是重置密码还是暂时允许不安全的 SHA256
  // 这里假设所有新用户都有 salt。如果是旧系统迁移，建议判断 salt 是否为空来通过不同逻辑验证。
  const salt = user.salt || ''; 
  
  // 计算输入密码的哈希
  const inputHash = await hashPassword(password, salt);

  // 比较哈希值
  if (inputHash !== user.password_hash) {
      log(reqId, 'WARN', `Login Failed: Wrong password`, { username });
      return errorResponse('用户或密码错误', 401);
  }
  
  log(reqId, 'INFO', `Login Success`, { username, uid: user.uid });
  const token = await signJwt({ uid: user.uid, username: user.username }, env.JWT_SECRET);
  return jsonResponse({ token, username });
}
async function changePassword(req, env, user) {
    // 假设调用链中透传了 reqId，如果没有，生成一个新的用于追踪
    const reqId = generateReqId(); 
    const { oldPassword, newPassword } = await req.json();

    if (!newPassword || newPassword.length < 5) {
        return errorResponse('新密码长度不能少于5位');
    }

    // 1. 获取当前用户的哈希和盐
    const dbUser = await env.DB.prepare('SELECT password_hash, salt FROM users WHERE uid = ?').bind(user.uid).first();
    
    if (!dbUser) {
        log(reqId, 'ERROR', 'Change Password: User not found in DB', { uid: user.uid });
        return errorResponse('用户不存在', 404);
    }

    // 2. 验证旧密码 (使用数据库中存储的盐)
    // 注意：需确保 hashPassword 函数已升级为支持 PBKDF2(password, salt)
    const currentSalt = dbUser.salt || ''; // 兼容旧数据
    const oldHashCalc = await hashPassword(oldPassword, currentSalt);

    if (oldHashCalc !== dbUser.password_hash) {
        log(reqId, 'WARN', 'Change Password Failed: Old password incorrect', { uid: user.uid });
        return errorResponse('旧密码错误', 403);
    }

    // 3. 生成新盐并加密新密码
    const newSalt = generateSalt();
    const newHash = await hashPassword(newPassword, newSalt);

    // 4. 更新数据库
    try {
        await env.DB.prepare('UPDATE users SET password_hash = ?, salt = ?, updated_at = ? WHERE uid = ?')
            .bind(newHash, newSalt, new Date().toISOString(), user.uid)
            .run();
        
        log(reqId, 'INFO', 'Password Changed Successfully', { uid: user.uid });
        return jsonResponse({ message: '修改成功' });
    } catch (e) {
        log(reqId, 'ERROR', 'Database Update Failed', { error: e.message });
        return errorResponse('系统错误', 500);
    }
}
function splitData(data, uid, id) {
    // Schema 中已存在的列，不应放入 JSON
    const coreMap = ['activity_type','datetime','duration','location','mood','satisfaction','orgasm_count','ejaculation_count','partner_name','sexual_position','stimulation'];
    const core = { uid, id, duration:0, satisfaction:0, orgasm_count:0, ejaculation_count:0 };
    const extra = {};
    for (let k in data) { 
        if (coreMap.includes(k)) core[k] = data[k]; 
        else if (k !== 'id' && k !== 'uid' && k !== 'created_at' && k !== 'acts') extra[k] = data[k]; 
    }
    // 确保数字字段类型正确
    ['duration','satisfaction','orgasm_count','ejaculation_count'].forEach(k => core[k] = parseInt(core[k]) || 0);
    return { core, extra };
}
// 将 Hex 字符串转为 Uint8Array
function hexToBuf(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// 将 Uint8Array 转为 Hex 字符串
function bufToHex(buf) {
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

// 生成随机盐 (16 bytes)
function generateSalt() {
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    return bufToHex(salt);
}
// 使用 PBKDF2 进行哈希
async function hashPassword(password, saltHex) {
    const enc = new TextEncoder();
    const salt = hexToBuf(saltHex);
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
    );
    const derivedBits = await crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        keyMaterial, 256
    );
    return bufToHex(derivedBits);
}
async function verifyAuth(request, env) { 
    // 强制要求环境变量
    if (!env.JWT_SECRET) {
        console.error('Missing JWT_SECRET in environment variables');
        return null; 
    }

    const h = request.headers.get('Authorization'); 
    if (!h || !h.startsWith('Bearer ')) return null; 
    try { 
        return await verifyJwt(h.split(' ')[1], env.JWT_SECRET); 
    } catch (e) { 
        return null; 
    } 
}
// [新增] 批量删除
async function batchDeleteRecords(req, env, user) {
    const { ids } = await req.json();
    if (!ids || !Array.isArray(ids) || ids.length === 0) return errorResponse('无有效ID');
    
    // 限制单次批量操作数量，防止超时
    if (ids.length > 50) return errorResponse('单次最多删除50条');

    // 使用 batch 构建批量语句，确保只能删除属于当前用户的记录
    const stmts = ids.map(id => 
        env.DB.prepare('DELETE FROM records WHERE id = ? AND uid = ?').bind(id, user.uid)
    );

    try {
        await env.DB.batch(stmts);
        return jsonResponse({ message: `成功删除 ${ids.length} 条记录` });
    } catch (e) {
        return errorResponse('批量删除失败');
    }
}
async function getDetailedStatistics(req, env, user, ctx) {
    // 缓存策略 (可选，建议缓存 1-5 分钟)
    const cacheUrl = new URL(req.url);
    const cacheKey = new Request(cacheUrl.toString(), req);
    const cache = caches.default;
    let response = await cache.match(cacheKey);
    if (response) return response;

    // 1. 标签云统计 (Tag Cloud)
    // 关联 users 表是为了确保只查当前用户 (虽然 record_acts 有 record_id，但为了安全最好 JOIN 检查 uid，或者依赖 record_id 的唯一性)
    // 这里采用 JOIN records 表来过滤 uid
    const tagsSql = `
        SELECT ra.act_type, count(*) as count 
        FROM record_acts ra
        JOIN records r ON ra.record_id = r.id
        WHERE r.uid = ?
        GROUP BY ra.act_type 
        ORDER BY count DESC 
        LIMIT 50
    `;

    // 2. 伴侣统计 (Partner Stats)
    const partnerSql = `
        SELECT partner_name, count(*) as count, avg(satisfaction) as avg_score
        FROM records 
        WHERE uid = ? AND activity_type = 'intercourse' AND partner_name IS NOT NULL AND partner_name != ''
        GROUP BY partner_name 
        ORDER BY count DESC 
        LIMIT 20
    `;
    
    // 3. 体位统计 (Position Stats) - 顺手加上
    const posSql = `
        SELECT sexual_position, count(*) as count
        FROM records
        WHERE uid = ? AND activity_type = 'intercourse' AND sexual_position IS NOT NULL
        GROUP BY sexual_position
        ORDER BY count DESC
    `;

    const [tagsRes, partnerRes, posRes] = await Promise.all([
        env.DB.prepare(tagsSql).bind(user.uid).all(),
        env.DB.prepare(partnerSql).bind(user.uid).all(),
        env.DB.prepare(posSql).bind(user.uid).all()
    ]);

    const data = {
        tags: tagsRes.results || [],
        partners: partnerRes.results || [],
        positions: posRes.results || []
    };

    response = jsonResponse(data);
    response.headers.set('Cache-Control', 'public, max-age=300'); // 缓存 5 分钟
    ctx.waitUntil(cache.put(cacheKey, response.clone()));
    return response;
}
// --- 生理周期逻辑 ---
async function getCycles(req, env, user) {
    const { results } = await env.DB.prepare('SELECT * FROM cycles WHERE uid = ? ORDER BY start_date DESC LIMIT 24').bind(user.uid).all();
    return jsonResponse(results);
}

async function addCycle(req, env, user) {
    const { start_date } = await req.json();
    const id = generateId();
    await env.DB.prepare('INSERT INTO cycles (id, uid, start_date) VALUES (?, ?, ?)').bind(id, user.uid, start_date).run();
    return jsonResponse({ id, message: '周期记录已添加' });
}

async function deleteCycle(url, env, user) {
    const id = url.searchParams.get('id');
    await env.DB.prepare('DELETE FROM cycles WHERE id = ? AND uid = ?').bind(id, user.uid).run();
    return jsonResponse({ message: '删除成功' });
}

// --- 核心算法：周期趋势分析 ---
async function getCycleTrends(req, env, user) {
    // 1. 获取最近一年的记录和周期数据
    const [recRes, cycRes] = await Promise.all([
        env.DB.prepare("SELECT datetime, satisfaction, activity_type FROM records WHERE uid = ? AND datetime > date('now', '-1 year')").all(),
        env.DB.prepare("SELECT start_date FROM cycles WHERE uid = ? AND start_date > date('now', '-1 year') ORDER BY start_date ASC").all()
    ]);

    const records = recRes.results;
    const cycles = cycRes.results;

    if (cycles.length === 0) return jsonResponse({ error: 'no_data' });

    // 2. 将记录映射到周期日 (Cycle Day 1-28)
    const cycleStats = new Array(30).fill(0).map(() => ({ count: 0, totalScore: 0 })); 
    
    records.forEach(r => {
        const rDate = new Date(r.datetime);
        // 找到该记录之前的最近一次月经开始日
        let lastCycle = null;
        for (let i = cycles.length - 1; i >= 0; i--) {
            const cDate = new Date(cycles[i].start_date);
            if (cDate <= rDate) {
                lastCycle = cDate;
                break;
            }
        }
        
        if (lastCycle) {
            // 计算是周期的第几天 (Day 1 是月经第一天)
            const diffTime = Math.abs(rDate - lastCycle);
            const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); 
            
            // 只统计标准周期内的数据 (例如前30天)
            if (diffDays > 0 && diffDays <= 29) {
                cycleStats[diffDays].count++;
                cycleStats[diffDays].totalScore += (r.satisfaction || 5);
            }
        }
    });

    // 3. 预测逻辑 (简化版：假设周期为28天)
    // 寻找 count 最高的区域作为"高欲望期"
    const analyzed = cycleStats.map((d, i) => ({
        day: i,
        avg_score: d.count ? (d.totalScore / d.count).toFixed(1) : 0,
        frequency: d.count
    })).slice(1); // 去掉索引0

    return jsonResponse({ trends: analyzed });
}

// --- 3D 可视化数据 ---
async function getGalaxyData(req, env, user) {
    // 仅查询必要的字段以减小体积，按时间倒序
    const { results } = await env.DB.prepare(`
        SELECT id, datetime, activity_type, satisfaction, duration, mood 
        FROM records 
        WHERE uid = ? 
        ORDER BY datetime DESC
    `).bind(user.uid).all();
    
    // 简化数据结构
    const points = results.map(r => {
        const d = new Date(r.datetime);
        return [
            // 0: 时间戳 (用于 Z 轴)
            d.getTime(),
            // 1: 一天中的分钟数 (0-1440) (用于 角度/X/Y)
            d.getHours() * 60 + d.getMinutes(),
            // 2: 满意度 (用于 大小/亮度)
            r.satisfaction,
            // 3: 类型 (0=masturbation, 1=intercourse) (用于 颜色)
            r.activity_type === 'intercourse' ? 1 : 0,
            // 4: 持续时间 (可选特效)
            r.duration
        ];
    });
    
    return jsonResponse(points);
}
async function signJwt(payload, secret) { const h = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' })); const b = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now()/1000)+604800 })); const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']); const s = await crypto.subtle.sign('HMAC', k, new TextEncoder().encode(`${h}.${b}`)); return `${h}.${b}.${b64url(s)}`; }
async function verifyJwt(token, secret) { const [h, b, s] = token.split('.'); const k = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']); if (!await crypto.subtle.verify('HMAC', k, b64urlDecode(s), new TextEncoder().encode(`${h}.${b}`))) throw new Error('Invalid'); const p = JSON.parse(new TextDecoder().decode(b64urlDecode(b))); if (p.exp < Date.now()/1000) throw new Error('Expired'); return p; }
function b64url(s) { return (typeof s==='string'?btoa(s):btoa(String.fromCharCode(...new Uint8Array(s)))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64urlDecode(s) { return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)); }
function jsonResponse(data, status = 200) { return new Response(JSON.stringify(data), { status, headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' } }); }
function errorResponse(msg, status = 400) { return jsonResponse({ error: msg }, status); }

// ==========================================
// 前端 HTML 生成函数
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
  <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
  <style>
    :root {
      --bg-deep: #050505;
      --primary: #d946ef; --secondary: #8b5cf6; --accent: #f43f5e;
      --glass-surface: rgba(25, 25, 30, 0.75); --glass-border: rgba(255, 255, 255, 0.1);
      --text-main: #f3f4f6; --text-muted: #9ca3af;
    }
    * { box-sizing: border-box; -webkit-tap-highlight-color: transparent; outline: none; }
    body { margin: 0; background-color: var(--bg-deep); color: var(--text-main); font-family: 'Noto Sans SC', sans-serif; min-height: 100vh; padding-bottom: 95px; overscroll-behavior-y: none; }
    
    .ambient-bg { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: -2; background: radial-gradient(circle at 10% 20%, #1a0b2e 0%, transparent 40%), radial-gradient(circle at 90% 80%, #2e0b1f 0%, transparent 40%), linear-gradient(to bottom, #0a0a0a, #050505); will-change: transform; }
    
    /* 核心组件 */
    .glass { background: var(--glass-surface); backdrop-filter: blur(15px); -webkit-backdrop-filter: blur(15px); border: 1px solid var(--glass-border); box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }
    .card { border-radius: 16px; padding: 20px; margin-bottom: 15px; position: relative; overflow: hidden; transition: transform 0.2s; }
    .btn { background: linear-gradient(135deg, var(--primary), var(--secondary)); color: white; border: none; border-radius: 12px; padding: 12px; font-weight: 600; width: 100%; cursor: pointer; transition: 0.2s; box-shadow: 0 4px 15px rgba(217, 70, 239, 0.3); }
    .btn:active { transform: scale(0.97); }
    .btn-outline { background: transparent; border: 1px solid rgba(255,255,255,0.2); box-shadow: none; }
    .btn-danger { background: linear-gradient(135deg, #ef4444, #b91c1c); box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3); }
    .container { max-width: 800px; margin: 0 auto; padding: 20px; }
    .hidden { display: none !important; }
    
    /* 动画与过渡 */
    .view-section {
        display: none;
        opacity: 0;
        transform: translateY(15px);
        transition: opacity 0.35s cubic-bezier(0.2, 0.8, 0.2, 1), transform 0.35s cubic-bezier(0.2, 0.8, 0.2, 1);
        will-change: opacity, transform;
    }
    .view-section.active { display: block; opacity: 1; transform: translateY(0); }
    
    /* 列表与虚拟滚动 */
    #listContainer { position: relative; }
    .virtual-spacer { width: 100%; position: absolute; top: 0; left: 0; z-index: -1; }
    
    /* 卡片与手势操作 */
    .record-card { 
        height: 90px; box-sizing: border-box; overflow: hidden;
        border-radius: 16px; background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.05); 
        margin-bottom: 10px; position: absolute; width: 100%; left: 0;
        touch-action: pan-y; /* 允许垂直滚动，拦截水平手势 */
    }
    .record-card-content {
        position: relative; z-index: 2; width: 100%; height: 100%;
        display: flex; align-items: center; padding: 16px;
        background: #151518; /* 必须有背景色遮挡底层按钮 */
        transition: transform 0.25s cubic-bezier(0.18, 0.89, 0.32, 1.28);
    }
    .record-card-actions {
        position: absolute; top: 0; right: 0; bottom: 0; width: 80px; z-index: 1;
        display: flex; align-items: center; justify-content: center;
    }
    .btn-swipe-del {
        width: 100%; height: 100%; border: none; background: #ef4444; color: #fff;
        display: flex; align-items: center; justify-content: center; cursor: pointer;
    }
    /* 激活状态：左滑 */
    .record-card.swiped .record-card-content { transform: translateX(-80px); }
    
    /* 搜索栏与建议 */
    .search-wrapper { position: relative; flex: 1; z-index: 50; }
    .search-input { width: 100%; background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 10px 35px 10px 15px; border-radius: 20px; font-size: 0.9rem; transition: 0.3s; }
    .search-input:focus { background: rgba(255,255,255,0.1); border-color: var(--primary); }
    .search-clear { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); width: 20px; height: 20px; background: rgba(255,255,255,0.2); border-radius: 50%; color: #000; display: flex; align-items: center; justify-content: center; font-size: 12px; cursor: pointer; opacity: 0; visibility: hidden; transition: 0.2s; }
    .search-wrapper.has-text .search-clear { opacity: 1; visibility: visible; }
    
    .suggestions-box { 
        position: absolute; top: 100%; left: 0; width: 100%; 
        background: #1a1a1a; border: 1px solid #333; border-radius: 12px; 
        margin-top: 5px; max-height: 200px; overflow-y: auto; 
        display: none; box-shadow: 0 10px 30px rgba(0,0,0,0.8); 
    }
    .suggestions-box.show { display: block; }
    .suggestion-item { padding: 12px 15px; color: #ccc; font-size: 0.9rem; border-bottom: 1px solid #222; cursor: pointer; transition: 0.2s; }
    .suggestion-item:last-child { border-bottom: none; }
    .suggestion-item:hover { background: rgba(255,255,255,0.05); color: var(--primary); }

    /* 热力图 */
    .heatmap-container { display: flex; flex-direction: column; gap: 4px; overflow-x: auto; padding-bottom: 10px; scrollbar-width: none; }
    .heatmap-container::-webkit-scrollbar { display: none; }
    .heatmap-grid { display: grid; grid-template-rows: repeat(7, 10px); grid-auto-flow: column; gap: 3px; }
    .heatmap-cell { width: 10px; height: 10px; border-radius: 2px; background: rgba(255,255,255,0.05); transition: 0.2s; }
    .heatmap-cell:hover { transform: scale(1.5); z-index: 10; border: 1px solid #fff; }
    .heatmap-cell[data-level="1"] { background: rgba(217, 70, 239, 0.3); }
    .heatmap-cell[data-level="2"] { background: rgba(217, 70, 239, 0.5); }
    .heatmap-cell[data-level="3"] { background: rgba(217, 70, 239, 0.8); }
    .heatmap-cell[data-level="4"] { background: #d946ef; box-shadow: 0 0 5px var(--primary); }

    /* 抽屉与表单 */
    .drawer-header { display: flex; justify-content: space-between; align-items: center; cursor: pointer; padding: 5px 0; }
    .drawer-arrow { font-size: 0.8rem; color: #666; transition: transform 0.3s ease; }
    .drawer-content { max-height: 0; overflow: hidden; transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1); border-top: 1px solid transparent; }
    .drawer-open .drawer-arrow { transform: rotate(180deg); color: var(--primary); }
    .drawer-open .drawer-content { border-top-color: rgba(255,255,255,0.05); padding-top: 20px; margin-top: 15px; }

    /* 图表 */
    .charts-wrapper { display: flex; flex-direction: row; gap: 15px; height: 220px; padding: 15px; }
    .chart-box-main { flex: 2; position: relative; min-width: 0; display: flex; align-items: center; }
    .chart-box-side { flex: 1; position: relative; max-width: 180px; display: flex; align-items: center; justify-content: center; }
    @media (max-width: 600px) {
        .charts-wrapper { flex-direction: column; height: auto; }
        .chart-box-main { width: 100%; height: 200px; flex: none; }
        .chart-box-side { width: 100%; height: 180px; max-width: none; flex: none; border-top: 1px solid rgba(255,255,255,0.05); margin-top: 10px; padding-top: 10px; }
    }

    /* 沉浸式计时器 */
    #immersiveTimer { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #000; z-index: 2000; display: none; flex-direction: column; align-items: center; justify-content: center; transition: opacity 0.3s; }
    .timer-display { font-family: 'Cinzel', monospace; font-size: 4rem; font-weight: bold; color: #fff; text-shadow: 0 0 20px var(--primary); margin-bottom: 40px; font-variant-numeric: tabular-nums; }
    .timer-btn-stop { width: 80px; height: 80px; border-radius: 50%; border: 2px solid var(--accent); background: rgba(244, 63, 94, 0.1); color: var(--accent); font-size: 1.5rem; cursor: pointer; display: flex; align-items: center; justify-content: center; transition: 0.3s; }
    .timer-btn-stop:active { background: var(--accent); color: #fff; transform: scale(0.9); }
    .pulse-ring { position: absolute; width: 200px; height: 200px; border-radius: 50%; border: 1px solid rgba(217, 70, 239, 0.3); animation: pulse 2s infinite; z-index: -1; }
    @keyframes pulse { 0% { transform: scale(0.8); opacity: 1; } 100% { transform: scale(1.5); opacity: 0; } }

    .timeline { position: relative; padding-left: 20px; border-left: 2px solid rgba(255,255,255,0.1); margin-left: 10px; }
    .timeline-item { position: relative; margin-bottom: 30px; }
    .timeline-dot { position: absolute; left: -26px; top: 0; width: 10px; height: 10px; border-radius: 50%; background: var(--bg-deep); border: 2px solid var(--primary); }
    .timeline-date { font-size: 0.8rem; color: var(--primary); font-weight: bold; margin-bottom: 5px; }
    .timeline-content { background: rgba(255,255,255,0.03); border-radius: 12px; padding: 12px; border: 1px solid rgba(255,255,255,0.05); transition: background 0.2s; }
    
    .dock-nav { position: fixed; bottom: 20px; left: 50%; transform: translateX(-50%); width: 95%; max-width: 480px; height: 60px; background: rgba(20, 20, 25, 0.9); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.1); border-radius: 30px; display: flex; justify-content: space-evenly; align-items: center; z-index: 100; box-shadow: 0 10px 30px rgba(0,0,0,0.6); padding: 0 5px; }
    .dock-item { display: flex; flex-direction: column; align-items: center; justify-content: center; color: #666; font-size: 0.65rem; gap: 3px; transition: 0.3s; width: 60px; height: 100%; cursor: pointer; }
    .dock-item svg { width: 22px; height: 22px; stroke: currentColor; stroke-width: 2; fill: none; transition: 0.3s; }
    .dock-item.active { color: var(--primary); }
    .dock-item.active svg { transform: translateY(-3px); stroke: var(--primary); }
    .dock-item.timer-btn { color: var(--accent); }
    .dock-item.timer-btn svg { width: 28px; height: 28px; filter: drop-shadow(0 0 5px rgba(244, 63, 94, 0.4)); }
    .dock-item.timer-btn.active { color: #fff; }
    .dock-item.timer-btn:active svg { transform: scale(0.9); }

    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 200; background: rgba(0,0,0,0.8); backdrop-filter: blur(5px); display: none; align-items: flex-end; justify-content: center; opacity: 0; transition: opacity 0.3s; }
    .modal-overlay.show { opacity: 1; }
    .modal-content { width: 100%; max-width: 600px; background: #111; border-radius: 24px 24px 0 0; padding: 25px 20px 40px; max-height: 90vh; overflow-y: auto; border-top: 1px solid #333; transform: translateY(100%); transition: transform 0.3s cubic-bezier(0.16, 1, 0.3, 1); }
    .modal-overlay.show .modal-content { transform: translateY(0); }

    .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; margin-bottom: 20px; }
    .stat-box { background: rgba(255,255,255,0.03); padding: 15px; border-radius: 16px; text-align: center; border: 1px solid rgba(255,255,255,0.05); }
    .stat-val { font-family: 'Cinzel', serif; font-size: 1.6rem; color: #fff; text-shadow: 0 0 10px rgba(255,255,255,0.3); }
    .stat-label { font-size: 0.7rem; color: var(--text-muted); margin-top: 4px; }
    
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
    .record-icon { width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; margin-right: 15px; background: rgba(0,0,0,0.3); flex-shrink: 0; }
    .user-avatar { width: 80px; height: 80px; border-radius: 50%; background-size: cover; background-position: center; background-color: #333; margin: 0 auto 15px; display: flex; align-items: center; justify-content: center; font-size: 2rem; border: 4px solid rgba(255,255,255,0.1); cursor:pointer; overflow: hidden; }
    .form-subtitle { font-size: 0.75rem; color: var(--secondary); margin: 15px 0 8px; font-weight: bold; border-left: 3px solid var(--secondary); padding-left: 8px; }
    .admin-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; color: #ccc; }
    .admin-table th { text-align: left; padding: 10px; color: #666; border-bottom: 1px solid #333; }
    .admin-table td { padding: 10px; border-bottom: 1px solid #222; }
    
    .about-content { padding: 30px 20px; text-align: center; }
    .about-logo { font-family: 'Cinzel'; font-size: 2rem; background: linear-gradient(to right, var(--primary), var(--secondary)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 10px; }
    .about-ver { font-size: 0.8rem; color: #666; margin-bottom: 20px; border: 1px solid #333; display: inline-block; padding: 2px 8px; border-radius: 10px; }

    /* [新增] 批量操作相关样式 */
    .batch-bar {
        position: fixed; 
        bottom: 90px; 
        left: 50%; 
        /* 关键修改：默认向下位移 200% 确保完全隐藏 */
        transform: translateX(-50%) translateY(200%);
        width: 90%; 
        max-width: 400px; 
        background: rgba(20,20,25,0.95);
        backdrop-filter: blur(10px); 
        border: 1px solid rgba(255,255,255,0.15);
        border-radius: 50px; 
        padding: 12px 25px;
        display: flex; 
        justify-content: space-between; 
        align-items: center;
        z-index: 99; 
        transition: transform 0.3s cubic-bezier(0.18, 0.89, 0.32, 1.28);
        box-shadow: 0 10px 40px rgba(0,0,0,0.5);
    }
    .batch-bar.show { transform: translateX(-50%) translateY(0); }

    .checkbox-overlay {
        position: absolute; top: 0; left: 0; width: 100%; height: 100%;
        background: rgba(0,0,0,0.6); z-index: 10; display: none;
        align-items: center; padding-left: 20px;
    }
    .record-card.batch-mode .checkbox-overlay { display: flex; }
    /* 自定义复选框 */
    .custom-chk {
        width: 24px; height: 24px; border-radius: 50%; border: 2px solid #666;
        display: flex; align-items: center; justify-content: center; transition: 0.2s;
        background: transparent;
    }
    .record-card.selected .custom-chk { background: var(--primary); border-color: var(--primary); }
    .custom-chk::after { content:'✓'; color:#fff; font-size:0.9rem; display:none; }
    .record-card.selected .custom-chk::after { display:block; }

    /* 修改 #galaxy-canvas 样式 */
    #galaxy-canvas { 
        position: fixed; top: 0; left: 0; width: 100%; height: 100%; 
        z-index: 50; 
        opacity: 0; 
        pointer-events: none; 
        transition: opacity 1s;
    }
    /* 新增 .visible 类用于控制显示 */
    #galaxy-canvas.visible {
        opacity: 1; 
        pointer-events: auto;
    }
    #view-galaxy.active ~ #galaxy-canvas {
        opacity: 1; pointer-events: auto;
    }
    
    /* 周期分析卡片 */
    .cycle-chart-bar {
        display: flex; align-items: flex-end; gap: 2px; height: 100px; 
        border-bottom: 1px solid #333; padding-bottom: 5px;
    }
    .c-bar { 
        flex: 1; background: #333; border-radius: 2px 2px 0 0; 
        position: relative; transition: 0.2s;
    }
    .c-bar:hover { background: var(--primary); }
    .c-bar.high-desire { background: linear-gradient(to top, var(--primary), var(--accent)); box-shadow: 0 0 10px var(--primary); }
    .phase-label { font-size: 0.6rem; color: #666; text-align: center; margin-top: 5px; }
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
  <div id="authScreen" style="position:fixed; top:0; left:0; width:100%; height:100%; z-index:1000; background:#050505; display:flex; flex-direction:column; align-items:center; justify-content:center; padding:30px; transition: opacity 0.4s;">
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
           <button id="btnBatchToggle" onclick="toggleBatchMode()" style="background:transparent; border:1px solid rgba(255,255,255,0.2); color:#aaa; width:32px; height:32px; border-radius:8px; display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:0.9rem;">⋮</button>
           <button onclick="openModal(false)" style="background:rgba(255,255,255,0.1); border:none; color:var(--primary); width:32px; height:32px; border-radius:50%; display:flex; align-items:center; justify-content:center; cursor:pointer; font-size:1.2rem; transition:0.2s;">+</button>
       </div>
    </header>

    <!-- 视图：首页 (Home) -->
    <div id="view-home" class="view-section active">
       <div class="stats-grid">
         <div class="stat-box"><div class="stat-val" id="sTotal">0</div><div class="stat-label">总次数</div></div>
         <div class="stat-box"><div class="stat-val" id="sDuration">0</div><div class="stat-label">均时长 (分)</div></div>
         <div class="stat-box"><div class="stat-val" id="sScore">0</div><div class="stat-label">满意度</div></div>
         <div class="stat-box"><div class="stat-val" id="sOrgasm" style="color:var(--primary);">0</div><div class="stat-label">总高潮</div></div>
       </div>

       <!-- 热力图 -->
       <div class="glass card" style="padding:15px; overflow-x:hidden;">
            <div style="font-size:0.8rem; color:#aaa; margin-bottom:10px;">年度活跃热力 (Activity Heatmap)</div>
            <div class="heatmap-container">
                <div class="heatmap-grid" id="heatmapGrid"></div>
            </div>
       </div>

       <div class="glass card charts-wrapper">
          <div class="chart-box-main"><canvas id="chartHistory"></canvas></div>
          <div class="chart-box-side"><canvas id="chartType"></canvas></div>
       </div>
       <!-- 时段分布图表 -->
       <div class="glass card" style="height: 180px; padding: 10px; margin-bottom: 15px;">
            <canvas id="chartHours"></canvas>
       </div>
       
       <!-- 搜索栏 -->
       <div style="display:flex; gap:10px; margin-bottom:15px;">
          <div class="search-wrapper" id="searchWrapper">
             <input type="text" class="search-input" id="searchInput" placeholder="搜索心情、地点、类型..." autocomplete="off">
             <div class="search-clear" onclick="clearSearch()">✕</div>
             <div id="searchSuggestions" class="suggestions-box"></div>
          </div>
          <select id="statsRange" style="width:90px; background:#222; border:1px solid rgba(255,255,255,0.1); color:#fff; border-radius:20px; padding:0 10px;" onchange="loadStats(this.value)">
             <option value="all">全部</option><option value="month">本月</option><option value="3_months">近3月</option><option value="year">今年</option>
          </select>
       </div>
       
       <div id="listContainer"></div>
       <!-- [新增] 批量操作浮动栏 -->
       <div id="batchBar" class="batch-bar">
           <span style="font-size:0.9rem; color:#ccc;">已选 <span id="batchCount" style="color:#fff; font-weight:bold;">0</span> 项</span>
           <button class="btn btn-danger" style="width:auto; padding:8px 20px; font-size:0.85rem;" onclick="execBatchDelete()">删除</button>
       </div>
       <div id="scrollSentinel" style="text-align:center; padding:20px; font-size:0.8rem; color:#555;">加载中...</div>
    </div>

    <!-- 视图：时光轨迹 (History) -->
    <div id="view-history" class="view-section">
       <h3 style="font-family:'Cinzel'; border-bottom:1px solid #333; padding-bottom:10px;">时光轨迹</h3>
       <div id="timelineContainer" class="timeline"></div>
       <div id="historySentinel" style="text-align:center; padding:10px; color:#555; font-size:0.8rem;">加载更多</div>
    </div>

    <!-- 视图：榜单 -->
    <div id="view-leaderboard" class="view-section">
       <h3 style="font-family:'Cinzel'; border-bottom:1px solid #333; padding-bottom:10px;">极乐名人堂</h3>
       <table style="width:100%; border-collapse:collapse; color:#ccc; font-size:0.9rem;">
          <thead><tr style="color:#666; font-size:0.8rem; text-align:left;"><th>#</th><th>玩家</th><th>时长</th><th>次数</th></tr></thead>
          <tbody id="leaderboardBody"></tbody>
       </table>
    </div>

    <!-- 视图：个人中心 -->
    <div id="view-profile" class="view-section">
       <div class="glass card" style="text-align:center; margin-top:20px;">
          <div class="user-avatar" id="avatarDisplay" onclick="toggleAvatarInput()">👤</div>
          <div id="avatarInputBox" class="hidden" style="margin-bottom:15px;">
             <input type="text" id="avatarUrlInput" placeholder="输入头像图片链接 (URL)" style="margin-bottom:5px;">
             <button class="btn btn-outline" style="padding:5px;" onclick="saveAvatar()">保存头像</button>
          </div>
          <h2 id="profileUser" style="margin:0 0 5px 0;">User</h2>
          <div style="font-size:0.8rem; color:#666;">秘密花园会员</div>
       </div>
       
       <!-- 安全设置 (抽屉样式) -->
       <div class="card" style="background:rgba(255,255,255,0.02); padding:0; overflow:hidden;" id="securityDrawer">
          <div class="drawer-header" onclick="toggleDrawer()" style="padding:20px;">
             <h4 style="margin:0;">安全设置</h4>
             <span class="drawer-arrow">▼</span>
          </div>
          <div class="drawer-content">
             <div style="padding:0 20px 20px 20px;">
                <div class="form-group"><input type="password" id="p-old" placeholder="当前密码"></div>
                <div class="form-group"><input type="password" id="p-new" placeholder="新密码 (至少5位)"></div>
                <button class="btn btn-outline" onclick="changePassword()">修改密码</button>
             </div>
          </div>
       </div>
       
       <div class="glass card" onclick="openAbout()" style="cursor:pointer; display:flex; justify-content:space-between; align-items:center;">
           <span>关于 Secret Garden</span>
           <span style="color:#666; font-size:0.8rem;">v7.7 ></span>
       </div>

       <button class="btn btn-outline" style="border-style:dashed; color:#666; margin-top:10px;" onclick="switchView('admin', null)">管理后台</button>
       <button class="btn" style="background:#333; color:#aaa; margin-top:20px;" onclick="logout()">退出登录</button>
    </div>

    <!-- 视图：欲望星球 (3D) -->
    <div id="view-galaxy" class="view-section">
        <div style="position: absolute; top: 20px; left: 20px; z-index: 60; pointer-events: none;">
            <h2 style="font-family:'Cinzel'; margin:0; text-shadow:0 0 10px #000;">Desire Galaxy</h2>
            <p style="font-size:0.8rem; color:#aaa;">拖动旋转 · 滚轮缩放 · 每一颗星都是一次回忆</p>
        </div>
        <!-- 3D Canvas 实际上是 fixed 的，这里只作为占位或控制层 -->
        <div style="position:absolute; bottom:100px; left:50%; transform:translateX(-50%); z-index:60; text-align:center;">
             <button class="btn" style="width:auto; padding:8px 20px; background:rgba(255,255,255,0.1); backdrop-filter:blur(5px);" onclick="resetCamera()">重置视角</button>
        </div>
    </div>

    <!-- 视图：生理周期 (Health) -->
    <div id="view-health" class="view-section">
        <h3 style="font-family:'Cinzel';">Bio-Rhythm</h3>

        <div class="glass card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">
                 <span>记录月经开始日</span>
                 <input type="date" id="cycleStartPicker" style="width:auto; padding:5px;">
                 <button class="btn" style="width:auto; padding:5px 15px;" onclick="addCycleRecord()">添加</button>
            </div>
            <div id="cycleList" style="max-height:100px; overflow-y:auto; font-size:0.8rem; color:#888;"></div>
        </div>

        <div class="glass card" id="cycleAnalysisBox">
            <h4>周期欲望趋势 (Desire Trends)</h4>
            <p style="font-size:0.8rem; color:#aaa; margin-bottom:10px;">基于历史数据分析你在周期第几天的活跃度。</p>
            <div class="cycle-chart-bar" id="cycleChart">
                <!-- JS 生成柱状图 -->
            </div>
            <div style="display:flex; justify-content:space-between; font-size:0.7rem; color:#555; margin-top:5px;">
                <span>Day 1 (经期)</span>
                <span>Day 14 (排卵)</span>
                <span>Day 28</span>
            </div>
            <div id="cyclePrediction" style="margin-top:15px; padding:10px; background:rgba(217,70,239,0.1); border-radius:8px; font-size:0.9rem; display:none;">
                🔮 预测：你的下一个<b>高欲望期</b>大约在 <span id="predDate" style="color:#fff; font-weight:bold;"></span>
            </div>
        </div>
    </div>

    <!-- 视图：管理后台 -->
    <div id="view-admin" class="view-section">
        <h3 style="font-family:'Cinzel'; color:var(--accent);">Admin Dashboard</h3>
        <div id="adminLoginBox">
            <p style="font-size:0.8rem; color:#888;">请输入管理员密码进行验证</p>
            <div style="display:flex; gap:10px;">
                <input type="password" id="adminPassInput" placeholder="管理员密码" style="flex:1;">
                <button class="btn" style="width:80px;" onclick="verifyAdmin()">验证</button>
            </div>
        </div>
        <div id="adminContent" class="hidden">
            <div class="stats-grid">
                <div class="stat-box"><div class="stat-val" id="admUsers">0</div><div class="stat-label">注册用户</div></div>
                <div class="stat-box"><div class="stat-val" id="admRecords">0</div><div class="stat-label">总记录数</div></div>
            </div>
            <p style="font-size:0.7rem; text-align:center; color:#555;">DB Size Est: <span id="admDbSize">-</span></p>
            <h4 style="border-bottom:1px solid #333; padding-bottom:10px; margin-top:20px;">用户管理</h4>
            <div style="overflow-x:auto;">
                <table class="admin-table">
                    <thead><tr><th>用户</th><th>注册/登录</th><th>记录</th><th>操作</th></tr></thead>
                    <tbody id="adminUserList"></tbody>
                </table>
            </div>
        </div>
    </div>
  </div>

  <!-- Dock 导航 -->
  <div class="dock-nav" id="dockNav">
    <div class="dock-item active" onclick="switchView('home', this)">
      <svg viewBox="0 0 24 24"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"></path><polyline points="9 22 9 12 15 12 15 22"></polyline></svg>
      <span>首页</span>
    </div>
    <div class="dock-item" onclick="switchView('history', this)">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
      <span>历史</span>
    </div>
    <div class="dock-item" onclick="switchView('health', this)">
        <svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"></path></svg>
        <span>健康</span>
    </div>
    <div class="dock-item timer-btn" onclick="startTimer()">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12"></polyline><line x1="12" y1="6" x2="12" y2="2"></line></svg>
      <span>计时</span>
    </div>
        <div class="dock-item" onclick="switchView('galaxy', this)">
        <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"></circle><path d="M2 12h20"></path><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path></svg>
        <span>星系</span>
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

  <!-- 关于弹窗 -->
  <div id="aboutOverlay" class="modal-overlay">
      <div class="modal-content">
          <div style="display:flex; justify-content:flex-end;">
              <span onclick="closeAbout()" style="font-size:1.5rem; color:#666; cursor:pointer;">&times;</span>
          </div>
          <div class="about-content">
              <div class="about-logo">Secret Garden</div>
              <div class="about-ver">v7.8 Heatmap & Gestures</div>
              <p style="color:#aaa; font-size:0.9rem; line-height:1.6;">
                  这里是你的私密花园，记录每一次真实的感受。<br>
                  数据存储于云端，仅你可见。<br>
                  愿你在这里找到属于自己的平静与欢愉。
              </p>
              <div style="margin-top:30px; border-top:1px solid #222; padding-top:20px; font-size:0.7rem; color:#444;">
                  &copy; 2026 Secret Garden Project<br>
                  Designed with Passion
              </div>
          </div>
      </div>
  </div>

  <script>
    let allRecords = []; // 存储所有已拉取的数据
    let virtualConfig = { itemHeight: 100, buffer: 5 }; // 卡片高度 + 边距
    let scrollTicking = false;
    let chart1, chart2, chart3; 
    let timerInterval = null;
    let isBatchMode = false;
    let selectedIds = new Set();
    
    const API = '/api';
    const TR_MAP = ${JSON.stringify(TR_MAP)};
    function tr(k) { return TR_MAP[k] || k; }

    function esc(s) {
        if (s === null || s === undefined) return "";
        return String(s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }
    
    let token = localStorage.getItem('sg_token');
    let user = localStorage.getItem('sg_user');
    let adminPass = localStorage.getItem('sg_admin_pass');
    
    let currentPage = 1, isLoading = false, hasMore = true;
    let historyPage = 1, historyLoading = false, historyHasMore = true;

    (function() {
      if(token) {
        const authScreen = document.getElementById('authScreen');
        authScreen.style.opacity = '0';
        setTimeout(() => authScreen.style.display='none', 400);

        document.getElementById('app').classList.remove('hidden');
        document.getElementById('profileUser').innerText = user;
        const avatar = localStorage.getItem('sg_avatar_'+user);
        if(avatar) document.getElementById('avatarDisplay').style.backgroundImage = \`url('\${avatar}')\`;
        
        loadStats();
        setupInfiniteScroll();
        checkTimerState();
        
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
    function openAbout() { document.getElementById('aboutOverlay').style.display = 'flex'; setTimeout(()=>document.getElementById('aboutOverlay').classList.add('show'),10); }
    function closeAbout() { document.getElementById('aboutOverlay').classList.remove('show'); setTimeout(()=>document.getElementById('aboutOverlay').style.display='none',300); }
    function toggleDrawer() {
        document.getElementById('securityDrawer').classList.toggle('drawer-open');
        const content = document.querySelector('#securityDrawer .drawer-content');
        if (document.getElementById('securityDrawer').classList.contains('drawer-open')) {
            content.style.maxHeight = content.scrollHeight + "px";
        } else {
            content.style.maxHeight = "0px";
        }
    }

    // --- Search Logic (Autocomplete) ---
    const searchInput = document.getElementById('searchInput');
    const suggestBox = document.getElementById('searchSuggestions');
    let searchDebounce;

    searchInput.addEventListener('input', (e) => {
        const val = e.target.value.trim();
        if(val.length > 0) document.getElementById('searchWrapper').classList.add('has-text');
        else document.getElementById('searchWrapper').classList.remove('has-text');

        clearTimeout(searchDebounce);
        
        if(val.length === 0) {
            suggestBox.classList.remove('show');
            resetList(); loadRecords(); 
            return;
        }

        // 防抖搜索
        searchDebounce = setTimeout(async () => {
            resetList(); loadRecords(); // 触发主列表搜索
            
            try {
                // 获取建议
                const r = await fetch(\`\${API}/search/suggest?q=\${encodeURIComponent(val)}\`, { headers: getHeaders() });
                const list = await r.json();
                if(list.length > 0) {
                    suggestBox.innerHTML = list.map(t => \`<div class="suggestion-item" onclick="applySearch('\${esc(t)}')">\${esc(t)}</div>\`).join('');
                    suggestBox.classList.add('show');
                } else {
                    suggestBox.classList.remove('show');
                }
            } catch(e) {}
        }, 300);
    });

    window.applySearch = function(text) {
        searchInput.value = text;
        suggestBox.classList.remove('show');
        resetList(); loadRecords();
    };

    function clearSearch() {
        searchInput.value = '';
        document.getElementById('searchWrapper').classList.remove('has-text');
        suggestBox.classList.remove('show');
        resetList(); loadRecords();
    }
    // 点击外部关闭建议
    document.addEventListener('click', (e) => {
        if(!document.getElementById('searchWrapper').contains(e.target)) suggestBox.classList.remove('show');
    });

    // --- Stats & Charts ---
    async function loadStats(range='all') {
        const r = await fetch(API+'/statistics?range='+range, { headers: getHeaders() });
        const s = await r.json();
        if(s.error === 'Unauthorized') return logout();
        
        document.getElementById('sTotal').innerText = s.total_records;
        document.getElementById('sDuration').innerText = Math.round(s.avg_duration);
        document.getElementById('sScore').innerText = s.avg_satisfaction;
        document.getElementById('sOrgasm').innerText = s.total_orgasms;
        
        // Render Heatmap
        renderHeatmap(s.daily_activity || {});

        // Charts
        Chart.defaults.color = '#666'; Chart.defaults.responsive = true; Chart.defaults.maintainAspectRatio = false;
        if(chart1) chart1.destroy(); if(chart2) chart2.destroy(); if(chart3) chart3.destroy();
        
        const ctx1 = document.getElementById('chartType').getContext('2d');
        chart1 = new Chart(ctx1, { type: 'doughnut', data: { labels: ['自慰','性爱'], datasets: [{ data: [s.masturbation, s.intercourse], backgroundColor: ['#d946ef', '#f43f5e'], borderWidth: 0 }] }, options: { maintainAspectRatio:false, cutout: '75%', plugins: { legend: { display: false } } } });
        
        const ctx2 = document.getElementById('chartHistory').getContext('2d');
        const labels = Object.keys(s.records_by_month).sort();
        chart2 = new Chart(ctx2, { type: 'bar', data: { labels: labels.map(l=>l.slice(5)), datasets: [{ label: '次', data: labels.map(k => s.records_by_month[k]), backgroundColor: '#8b5cf6', borderRadius: 4 }] }, options: { maintainAspectRatio:false, scales: { x: { grid: {display:false} }, y: { display:false } }, plugins: { legend: {display:false} } } });
        
        const ctx3 = document.getElementById('chartHours').getContext('2d');
        const gradient = ctx3.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(217, 70, 239, 0.5)');
        gradient.addColorStop(1, 'rgba(217, 70, 239, 0)');

        chart3 = new Chart(ctx3, {
            type: 'line',
            data: {
                labels: Array.from({length:24}, (_,i)=>i),
                datasets: [{ label: '活跃时段', data: s.hour_distribution, borderColor: '#d946ef', backgroundColor: gradient, fill: true, tension: 0.4, pointRadius: 2 }]
            },
            options: {
                maintainAspectRatio: false,
                plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
                scales: { x: { grid: { display: false, color:'#333' }, ticks: { color: '#666', maxTicksLimit: 8 } }, y: { display: false } }
            }
        });

        if(currentPage===1) loadRecords();
    }

    function renderHeatmap(data) {
        const container = document.getElementById('heatmapGrid');
        container.innerHTML = '';
        const today = new Date();
        const startDate = new Date();
        startDate.setDate(today.getDate() - 364); // 过去一年
        
        for(let i=0; i<365; i++) {
            const d = new Date(startDate);
            d.setDate(startDate.getDate() + i);
            const dateStr = d.toISOString().split('T')[0];
            const count = data[dateStr] || 0;
            let level = 0;
            if(count > 0) level = 1;
            if(count > 2) level = 2;
            if(count > 4) level = 3;
            if(count > 6) level = 4;
            
            const cell = document.createElement('div');
            cell.className = 'heatmap-cell';
            cell.dataset.level = level;
            cell.title = \`\${dateStr}: \${count}次\`;
            container.appendChild(cell);
        }
    }

    // --- Virtual Scroll List ---
    function resetList() { currentPage=1; hasMore=true; allRecords = []; }
    async function loadRecords() {
        if(isLoading || !hasMore) return; 
        isLoading = true;
        const q = document.getElementById('searchInput').value;
        if(currentPage === 1) {
            allRecords = [];
            document.getElementById('listContainer').innerHTML = '<div class="virtual-spacer" id="vSpacer"></div>';
        }
        const r = await fetch(\`\${API}/records?page=\${currentPage}&search=\${q}\`, { headers: getHeaders() });
        const d = await r.json();

        if(d.records.length === 0) { 
            hasMore = false; 
            document.getElementById('scrollSentinel').innerText = '—— 到底了 ——'; 
        } else { 
            const processed = d.records.map(item => {
                const isM = item.activity_type === 'masturbation';
                const dateObj = new Date(item.datetime);
                return {
                    ...item,
                    isM,
                    dateStr: \`\${dateObj.getMonth()+1}/\${dateObj.getDate()} \${dateObj.getHours()}:\${dateObj.getMinutes().toString().padStart(2,'0')}\`,
                    locStr: esc(tr(item.location||'unknown')),
                    tags: [item.mood ? tr(item.mood) : null, isM && item.stimulation ? tr(item.stimulation) : null].filter(Boolean)
                };
            });
            allRecords = [...allRecords, ...processed];
            currentPage++;
            updateVirtualSpacer();
            renderVirtualList();
        }
        isLoading = false;
    }
    function updateVirtualSpacer() {
        const spacer = document.getElementById('vSpacer');
        if(spacer) spacer.style.height = (allRecords.length * virtualConfig.itemHeight) + 'px';
    }
    function renderVirtualList() {
        if (!document.getElementById('view-home').classList.contains('active')) return;
        const container = document.getElementById('listContainer');
        const scrollTop = window.scrollY;
        const viewportHeight = window.innerHeight;
        const startIndex = Math.max(0, Math.floor(scrollTop / virtualConfig.itemHeight) - virtualConfig.buffer);
        const endIndex = Math.min(allRecords.length, Math.ceil((scrollTop + viewportHeight) / virtualConfig.itemHeight) + virtualConfig.buffer);
        
        const existingNodes = new Map();
        container.querySelectorAll('.record-card').forEach(node => existingNodes.set(parseInt(node.dataset.index), node));
        
        existingNodes.forEach((node, idx) => { if (idx < startIndex || idx >= endIndex) node.remove(); });

        for (let i = startIndex; i < endIndex; i++) {
            if (!existingNodes.has(i)) {
                const item = allRecords[i];
                if (!item) continue;
                
                const div = document.createElement('div');
                const isSelected = selectedIds.has(item.id); // 检查是否选中
                div.className = \`record-card \${item.isM?'type-m':'type-i'} \${isBatchMode?'batch-mode':''} \${isSelected?'selected':''}\`;
                div.dataset.index = i;
                div.style.top = (i * virtualConfig.itemHeight) + 'px';
                
                if (isBatchMode) {
                    // 批量模式下点击整卡片切换选中
                    div.onclick = () => toggleSelection(item.id);
                } else {
                    // 普通模式逻辑 (保留原有的手势和点击编辑)
                    let startX = 0, currentX = 0;
                    div.addEventListener('touchstart', (e) => {
                        startX = e.touches[0].clientX;
                        document.querySelectorAll('.record-card.swiped').forEach(el => { if(el!==div) el.classList.remove('swiped'); });
                    }, {passive: true});
                    div.addEventListener('touchmove', (e) => { currentX = e.touches[0].clientX; }, {passive: true});
                    div.addEventListener('touchend', (e) => {
                        const diff = startX - currentX;
                        if (diff > 50) div.classList.add('swiped'); 
                        else if (diff < -50) div.classList.remove('swiped');

                        if (Math.abs(diff) < 10) { 
                            if(!e.target.closest('.btn-swipe-del')) editRecord(esc(item.id));
                        }
                    });
                }

                div.innerHTML = \`
                    <div class="record-card-content">
                        <div class="record-icon">\${item.isM ? '🖐' : '❤️'}</div>
                        <div style="flex:1;">
                            <div style="display:flex; justify-content:space-between; color:#eee; font-weight:600; margin-bottom:4px;">
                                <span>\${item.locStr}</span>
                                <span style="color:\${item.isM?'var(--primary)':'var(--accent)'}">\${item.duration}分</span>
                            </div>
                            <div style="font-size:0.8rem; color:#888;">\${item.dateStr} · \${item.satisfaction}/10</div>
                            <div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap;">
                                \${item.tags.map(t=>\`<span style="background:rgba(255,255,255,0.1); padding:2px 6px; border-radius:4px; font-size:0.7rem;">\${esc(t)}</span>\`).join('')}
                            </div>
                        </div>
                    </div>
                    <div class="record-card-actions">
                        <button class="btn-swipe-del" onclick="quickDelete('\${esc(item.id)}', this)">
                           <svg viewBox="0 0 24 24" width="24" height="24" stroke="currentColor" stroke-width="2" fill="none"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                        </button>
                    </div>\`;
                container.appendChild(div);
            } else {
                // [新增] 如果节点已存在，更新其选中样式（防止复用时样式不同步）
                const existingNode = existingNodes.get(i);
                const item = allRecords[i];

                if (isBatchMode) existingNode.classList.add('batch-mode');
                else existingNode.classList.remove('batch-mode');

                if (selectedIds.has(item.id)) existingNode.classList.add('selected');
                else existingNode.classList.remove('selected');

                // 动态切换事件处理有点复杂，重新生成节点通常更简单。
                // 但为了性能，这里我们假设切换模式时，上方的 toggleBatchMode 里的 renderVirtualList 会触发重绘。
                // 由于 renderVirtualList 里的 existingNodes 逻辑是跳过已存在的，
                // 所以我们需要在 toggleBatchMode 里先清空 container innerHTML 强制重绘，或者在这里更新 onclick。
                // 简单方案：在 toggleBatchMode 中设置 listContainer.innerHTML = '' 并重置 existingNodes 逻辑。
            }
        }
    }
    window.addEventListener('scroll', () => {
        if (!scrollTicking) {
            window.requestAnimationFrame(() => { renderVirtualList(); scrollTicking = false; });
            scrollTicking = true;
        }
    });

    async function quickDelete(id, btnEl) {
        if(!confirm('确定删除?')) return;
        const card = btnEl.closest('.record-card');
        card.style.height = '0'; card.style.margin = '0'; card.style.border = 'none';
        
        const r = await fetch(API+'/records?id='+id, { method:'DELETE', headers: getHeaders() });
        const d = await r.json();
        if(d.message) {
            setTimeout(() => { resetList(); loadRecords(); loadStats(); }, 300);
        } else alert('Error');
    }

    // --- Admin & History ---
    async function verifyAdmin() {
        const p = document.getElementById('adminPassInput').value;
        adminPass = p; 
        const r = await fetch(API+'/admin/stats', { headers: getHeaders() }); 
        if(r.status === 200) {
            localStorage.setItem('sg_admin_pass', p);
            document.getElementById('adminLoginBox').classList.add('hidden');
            document.getElementById('adminContent').classList.remove('hidden');
            loadAdminData();
        } else {
            alert('验证失败'); adminPass = null;
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
        const tbody = document.getElementById('adminUserList');
        tbody.innerHTML = '';
        users.forEach(u => {
            const regDate = new Date(u.created_at).toLocaleDateString();
            // [新增] 格式化最后登录时间
            let lastLogin = '-';
            if (u.last_login_attempt) {
                const ld = new Date(u.last_login_attempt);
                lastLogin = \`\${ld.getMonth()+1}/\${ld.getDate()} \${ld.getHours()}:\${ld.getMinutes().toString().padStart(2,'0')}\`;
            }
            
            tbody.insertAdjacentHTML('beforeend', \`
                <tr>
                    <td>
                        <div style="font-weight:bold; color:#fff;">\${esc(u.username)}</div>
                        <div style="font-size:0.7rem; color:#666;">UID: \${u.uid.substring(0,6)}...</div>
                    </td>
                    <td>
                        <div style="font-size:0.8rem;">\${regDate}</div>
                        <div style="font-size:0.7rem; color:\${u.last_login_attempt?'var(--primary)':'#666'}">\${lastLogin}</div>
                    </td>
                    <td style="text-align:center;">\${u.rec_count}</td>
                    <td>
                        <div style="display:flex; gap:5px;">
                            <button style="background:#333; color:#ccc; border:1px solid #444; padding:4px 8px; border-radius:4px; font-size:0.7rem; cursor:pointer;" onclick="adminResetUser('\${u.uid}', '\${esc(u.username)}')">重置</button>
                            <button style="background:#7f1d1d; color:#fca5a5; border:none; padding:4px 8px; border-radius:4px; font-size:0.7rem; cursor:pointer;" onclick="deleteUser('\${u.uid}')">删除</button>
                        </div>
                    </td>
                </tr>
            \`);
        });
    }
    // [新增] 管理员重置密码
    async function adminResetUser(uid, name) {
        const newPass = prompt(\`重置用户 [\${name}] 的密码为:\`);
        if(!newPass || newPass.length < 5) {
            if(newPass) alert('密码太短');
            return;
        }

        const r = await fetch(API + '/admin/users/reset', {
            method: 'POST',
            headers: getHeaders(),
            body: JSON.stringify({ uid, newPassword: newPass })
        });
        const d = await r.json();
        alert(d.message || d.error);
    }
    async function deleteUser(uid) {
        if(!confirm('Dangerous! Delete user?')) return;
        const r = await fetch(API+'/admin/users?uid='+uid, { method:'DELETE', headers: getHeaders() });
        if(r.status===200) loadAdminData();
    }

    async function loadHistory() {
        if (historyLoading || !historyHasMore) return;
        historyLoading = true;
        try {
            const r = await fetch(\`\${API}/records?page=\${historyPage}\`, { headers: getHeaders()});
            const d = await r.json();
            const c = document.getElementById('timelineContainer');
            if (!d.records || d.records.length === 0) { 
                historyHasMore = false; 
                document.getElementById('historySentinel').innerText = '一切的开始'; 
            } else {
                d.records.forEach(item => {
                    const isM = item.activity_type === 'masturbation';
                    const dateObj = new Date(item.datetime);
                    const timeStr = \`\${dateObj.getFullYear()}-\${(dateObj.getMonth()+1).toString().padStart(2,'0')}-\${dateObj.getDate().toString().padStart(2,'0')} \${dateObj.getHours().toString().padStart(2,'0')}:\${dateObj.getMinutes().toString().padStart(2,'0')}\`;
                    const safeId = esc(item.id);
                    const safeLocation = esc(tr(item.location || 'unknown'));
                    const html = \`<div class="timeline-item"><div class="timeline-dot" style="border-color:\${isM ? 'var(--primary)' : 'var(--accent)'}"></div><div class="timeline-date">\${timeStr}</div><div class="timeline-content" onclick="editRecord('\${safeId}')"><div style="display:flex; justify-content:space-between; margin-bottom:5px;"><strong style="color:#fff">\${isM ? '独享' : '欢愉'} · \${safeLocation}</strong><span>\${item.duration} 分钟</span></div><div style="font-size:0.85rem; color:#aaa; white-space: pre-wrap;">\${esc(item.experience || '无备注...')}</div></div></div>\`;
                    c.insertAdjacentHTML('beforeend', html);
                });
                historyPage++;
            }
        } catch (e) {} finally { historyLoading = false; }
    }
    // [新增] 切换批量模式
    function toggleBatchMode() {
        isBatchMode = !isBatchMode;
        const btn = document.getElementById('btnBatchToggle');
        const bar = document.getElementById('batchBar');

        if (isBatchMode) {
            btn.style.borderColor = 'var(--primary)';
            btn.style.color = 'var(--primary)';
            bar.classList.add('show');
        } else {
            btn.style.borderColor = 'rgba(255,255,255,0.2)';
            btn.style.color = '#aaa';
            bar.classList.remove('show');
            selectedIds.clear();
            updateBatchUI();
        }
        document.getElementById('listContainer').innerHTML = '<div class="virtual-spacer" id="vSpacer"></div>';
        updateVirtualSpacer(); // 恢复高度
        renderVirtualList(); // 重新生成 DOM
    }

    // [新增] 选中/取消选中
    function toggleSelection(id) {
        if (selectedIds.has(id)) selectedIds.delete(id);
        else selectedIds.add(id);
        updateBatchUI();
        renderVirtualList(); // 更新高亮状态
    }

    // [新增] 更新UI计数
    function updateBatchUI() {
        document.getElementById('batchCount').innerText = selectedIds.size;
    }

    // [新增] 执行批量删除
    async function execBatchDelete() {
        if (selectedIds.size === 0) return;
        if (!confirm(\`确定要删除选中的 \${selectedIds.size} 条记录吗？\`)) return;

        const ids = Array.from(selectedIds);
        const r = await fetch(API + '/records/batch', {
            method: 'DELETE',
            headers: getHeaders(),
            body: JSON.stringify({ ids })
        });
        const d = await r.json();

        alert(d.message || d.error);
        if (!d.error) {
            toggleBatchMode(); // 退出批量模式
            resetList(); 
            loadRecords();
            loadStats();
        }
    }

    // --- Timer ---
    function checkTimerState() { const start = localStorage.getItem('timerStart'); if(start) { showTimerOverlay(parseInt(start)); } }
    function startTimer() { const now = Date.now(); localStorage.setItem('timerStart', now); showTimerOverlay(now); }
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
            localStorage.removeItem('timerStart'); clearInterval(timerInterval);
            document.getElementById('immersiveTimer').style.display = 'none';
            openModal(false); document.getElementById('duration').value = min; document.getElementById('vDur').innerText = min;
        }
    }

    // --- CRUD Forms ---
    function setActType(type) {
        document.getElementById('actType').value = type;
        document.querySelectorAll('.segment-opt').forEach(el => el.classList.toggle('active', el.dataset.val === type));
        document.getElementById('secMasturbation').classList.toggle('hidden', type !== 'masturbation');
        document.getElementById('secIntercourse').classList.toggle('hidden', type !== 'intercourse');
    }
    function openModal(isEdit) {
        document.getElementById('modalOverlay').style.display = 'flex';
        setTimeout(()=>document.getElementById('modalOverlay').classList.add('show'), 10);
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
    function closeModal() { document.getElementById('modalOverlay').classList.remove('show'); setTimeout(()=>document.getElementById('modalOverlay').style.display='none',300); }
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
       if(document.getElementById('view-history').classList.contains('active')) { 
           historyPage=1; document.getElementById('timelineContainer').innerHTML=''; historyHasMore=true; loadHistory();
       }
    }
    async function deleteCurrentRecord() {
       const id = document.getElementById('recordId').value;
       if(!id || !confirm('Confirm delete?')) return;
       const r = await fetch(API+'/records?id='+id, { method:'DELETE', headers: getHeaders() });
       const d = await r.json();
       if(d.error) { alert('Error: '+d.error); return; }
       closeModal(); resetList(); loadRecords(); loadStats();
       if(document.getElementById('view-history').classList.contains('active')) {
           historyPage=1; document.getElementById('timelineContainer').innerHTML=''; historyHasMore=true; loadHistory();
       }
    }
    
    function switchView(v, el) {
        document.querySelectorAll('.dock-item').forEach(d => d.classList.remove('active'));
        if(el) el.classList.add('active');
        document.querySelectorAll('.view-section').forEach(view => {
            if(view.id === 'view-'+v) view.classList.add('active'); else view.classList.remove('active');
        });
        if(v==='leaderboard') loadLeaderboard();
        if(v==='history' && document.getElementById('timelineContainer').innerHTML==='') loadHistory();
        if(v==='admin' && adminPass) loadAdminData();
    }
    async function loadLeaderboard() {
        const r = await fetch(API+'/leaderboard', { headers: getHeaders() });
        const list = await r.json();
        const b = document.getElementById('leaderboardBody'); b.innerHTML = '';
        list.forEach((i, idx) => { b.insertAdjacentHTML('beforeend', \`<tr style="border-bottom:1px solid #222"><td style="padding:12px; color:\${idx<3?'var(--primary)':'#666'}">\${idx+1}</td><td>\${esc(i.username)}</td><td>\${Math.round(i.total_duration/60)}h</td><td>\${i.total_records}</td></tr>\`); });
    }
    function setupInfiniteScroll() { 
        const obs = new IntersectionObserver(e=>{if(e[0].isIntersecting) loadRecords()}); obs.observe(document.getElementById('scrollSentinel'));
        const obsH = new IntersectionObserver(e=>{if(e[0].isIntersecting) loadHistory()}); obsH.observe(document.getElementById('historySentinel'));
    }
    
    // ==========================================
    // 3D 欲望星球 (Three.js Implementation)
    // ==========================================
    let scene, camera, renderer, particles, controls;
    let animationId;

    function initGalaxy() {
        if(scene) return; // 只初始化一次

        const canvasContainer = document.createElement('div');
        canvasContainer.id = 'galaxy-canvas';
        document.body.appendChild(canvasContainer);

        scene = new THREE.Scene();
        // 增加一点环境雾效
        scene.fog = new THREE.FogExp2(0x050505, 0.002);

        camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 2000);
        camera.position.set(0, 100, 300); // 初始视角

        renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        canvasContainer.appendChild(renderer.domElement);

        controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.5;

        // 窗口大小调整
        window.addEventListener('resize', () => {
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        });
    }

    async function loadGalaxyData() {
        const r = await fetch(API + '/visualization/galaxy', { headers: getHeaders() });
        const points = await r.json();
        createStarSystem(points);
    }

    function createStarSystem(data) {
        if(particles) scene.remove(particles);

        const geometry = new THREE.BufferGeometry();
        const positions = [];
        const colors = [];
        const sizes = [];

        const color1 = new THREE.Color('#d946ef'); // Masturbation (Pink/Purple)
        const color2 = new THREE.Color('#f43f5e'); // Intercourse (Red/Rose)

        // 螺旋星系参数
        const spiralTightness = 0.2; 

        data.forEach((p, i) => {
            // 解构数据 [timestamp, minuteOfDay, satisfaction, type, duration]
            const time = p[0]; 
            const minOfDay = p[1]; // 0-1440
            const score = p[2];
            const type = p[3];

            // 核心算法：将时间转化为空间坐标
            // Z轴：时间轴 (越新的越靠近 0，越旧的越深)
            const z = (Date.now() - time) / 86400000 * 5; // 每天间距 5 单位

            // 角度：基于一天中的时间 (0点在上方)
            const angle = (minOfDay / 1440) * Math.PI * 2;

            // 半径：基于"螺旋" + 随机偏移 (形成星云感)
            // 越久远的记录扩散得越开，形成漏斗状或隧道状
            const baseRadius = 50 + (Math.random() * 20); 

            const x = Math.cos(angle) * baseRadius;
            const y = Math.sin(angle) * baseRadius;

            positions.push(x, y, -z);

            // 颜色
            const color = type === 1 ? color2 : color1;
            // 满意度越高，颜色越亮/白
            const mixedColor = color.clone().lerp(new THREE.Color('#ffffff'), (score - 5) / 10);
            colors.push(mixedColor.r, mixedColor.g, mixedColor.b);

            // 大小
            sizes.push(score * 1.5);
        });

        geometry.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3));
        geometry.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3));
        geometry.setAttribute('size', new THREE.Float32BufferAttribute(sizes, 1));

        // 粒子材质
        const material = new THREE.PointsMaterial({
            size: 4,
            vertexColors: true,
            map: getTexture(), // 生成一个发光圆点贴图
            blending: THREE.AdditiveBlending,
            depthWrite: false,
            transparent: true,
            opacity: 0.8
        });

        particles = new THREE.Points(geometry, material);
        scene.add(particles);
    }

    // 辅助：生成粒子贴图
    function getTexture() {
        const canvas = document.createElement('canvas');
        canvas.width = 32; canvas.height = 32;
        const ctx = canvas.getContext('2d');
        const grad = ctx.createRadialGradient(16,16,0,16,16,16);
        grad.addColorStop(0, 'rgba(255,255,255,1)');
        grad.addColorStop(0.4, 'rgba(255,255,255,0.5)');
        grad.addColorStop(1, 'rgba(0,0,0,0)');
        ctx.fillStyle = grad; ctx.fillRect(0,0,32,32);
        const texture = new THREE.Texture(canvas);
        texture.needsUpdate = true;
        return texture;
    }

    function animateGalaxy() {
        animationId = requestAnimationFrame(animateGalaxy);
        if(controls) controls.update();

        // 微弱的星空闪烁
        if(particles) {
            // 这里可以做一些动态效果，比如粒子轻微浮动
        }

        renderer.render(scene, camera);
    }

    function startGalaxy() {
        initGalaxy();
        loadGalaxyData();
        animateGalaxy();
        // 强制显示 Canvas
        const canvas = document.getElementById('galaxy-canvas');
        if(canvas) canvas.classList.add('visible');
    }

    function stopGalaxy() {
        if(animationId) cancelAnimationFrame(animationId);
        // 隐藏 Canvas
        const canvas = document.getElementById('galaxy-canvas');
        if(canvas) canvas.classList.remove('visible');
    }
    function resetCamera() {
        controls.reset();
        camera.position.set(0, 100, 300);
    }

    // ==========================================
    // 生理周期逻辑
    // ==========================================
    async function loadCycles() {
        const r = await fetch(API + '/cycles', { headers: getHeaders() });
        const list = await r.json();
        const box = document.getElementById('cycleList');
        box.innerHTML = list.map(c => 
            \`<div style="display:flex; justify-content:space-between; padding:5px 0; border-bottom:1px solid #222;">
                <span>🩸 \${c.start_date}</span>
                <span style="color:#f43f5e; cursor:pointer;" onclick="delCycle('\${c.id}')">×</span>
            </div>\`
        ).join('');

        // 加载趋势
        loadCycleTrends();
    }

    async function addCycleRecord() {
        const d = document.getElementById('cycleStartPicker').value;
        if(!d) return;
        await fetch(API + '/cycles', { method:'POST', headers: getHeaders(), body: JSON.stringify({start_date: d}) });
        loadCycles();
    }

    async function delCycle(id) {
        if(!confirm('删除此记录?')) return;
        await fetch(API + '/cycles?id='+id, { method:'DELETE', headers: getHeaders() });
        loadCycles();
    }

    async function loadCycleTrends() {
        const r = await fetch(API + '/analysis/cycle-trends', { headers: getHeaders() });
        const d = await r.json();
        if(d.error) return; // 数据不足

        const chart = document.getElementById('cycleChart');
        chart.innerHTML = '';

        // 找出最大值用于归一化高度
        const maxCount = Math.max(...d.trends.map(t => t.frequency));

        d.trends.forEach(t => {
            const h = (t.frequency / maxCount) * 100;
            const isHigh = t.day >= 12 && t.day <= 16; // 简单的排卵期高亮

            const bar = document.createElement('div');
            bar.className = 'c-bar ' + (isHigh ? 'high-desire' : '');
            bar.style.height = (h || 2) + '%';
            bar.title = \`Day \${t.day}: \${t.frequency}次 (均分 \${t.avg_score})\`;
            chart.appendChild(bar);
        });

        // 简单预测
        // 假设最后一次月经是列表里的第一个（因为是 start_date DESC）
        const listNodes = document.getElementById('cycleList').children;
        if(listNodes.length > 0) {
            const lastDateStr = listNodes[0].querySelector('span').innerText.replace('🩸 ', '');
            const lastDate = new Date(lastDateStr);
            // 预测排卵期 (Day 14)
            lastDate.setDate(lastDate.getDate() + 14);
            const predBox = document.getElementById('cyclePrediction');
            predBox.style.display = 'block';
            document.getElementById('predDate').innerText = lastDate.toLocaleDateString();
        }
    }

    // ==========================================
    // 修改 switchView 函数以集成新视图
    // ==========================================
    // 保存旧的 switchView 引用如果需要，或者直接覆盖
    const originalSwitchView = window.switchView || function(){};
    window.switchView = function(v, el) {
        // 处理 Dock 激活状态
        document.querySelectorAll('.dock-item').forEach(d => d.classList.remove('active'));
        if(el) el.classList.add('active');

        // 处理视图切换
        document.querySelectorAll('.view-section').forEach(view => {
            if(view.id === 'view-'+v) view.classList.add('active'); 
            else view.classList.remove('active');
        });

        // 特定视图逻辑
        if (v === 'galaxy') startGalaxy();
        else stopGalaxy(); // 离开 3D 视图时停止渲染节省电量

        if (v === 'health') loadCycles();
        if (v === 'leaderboard') loadLeaderboard();
        if (v === 'history' && document.getElementById('timelineContainer').innerHTML==='') loadHistory();
        if (v === 'admin' && adminPass) loadAdminData();
    }
  </script>
</body>
</html>
  `;
  return new Response(html, { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}