-- ============================================
-- 1. 用户表
-- ============================================
CREATE TABLE users (
    uid TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL DEFAULT '',
    login_attempts INTEGER DEFAULT 0,
    last_login_attempt TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ============================================
-- 2. 记录表 (主表)
-- ============================================
CREATE TABLE records (
    id TEXT PRIMARY KEY,
    uid TEXT NOT NULL,
    activity_type TEXT NOT NULL,
    datetime TEXT NOT NULL,
    duration INTEGER DEFAULT 0,
    satisfaction INTEGER DEFAULT 0,
    orgasm_count INTEGER DEFAULT 0,
    ejaculation_count INTEGER DEFAULT 0,
    location TEXT,
    mood TEXT,
    stimulation TEXT,
    partner_name TEXT,
    sexual_position TEXT,
    data_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now')),
    
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE,
    
    -- 数据完整性约束 (移除复杂的日期正则检查，性能更好)
    CHECK (activity_type IN ('masturbation', 'intercourse')),
    CHECK (duration BETWEEN 0 AND 1440),
    CHECK (satisfaction BETWEEN 0 AND 10),
    CHECK (orgasm_count >= 0),
    CHECK (ejaculation_count >= 0)
);

-- ============================================
-- 3. 行为标签关联表
-- ============================================
CREATE TABLE record_acts (
    record_id TEXT NOT NULL,
    act_type TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    
    -- 复合主键自动为 record_id 提供索引能力
    PRIMARY KEY (record_id, act_type),
    FOREIGN KEY (record_id) REFERENCES records(id) ON DELETE CASCADE
);

-- ============================================
-- 4. 全文检索虚拟表 (FTS5)
-- ============================================
CREATE VIRTUAL TABLE records_fts USING fts5(
    record_id UNINDEXED, 
    uid UNINDEXED,
    content
);

-- ============================================
-- 索引优化
-- ============================================

-- 组合索引：最常用的查询模式 (用户+时间)
CREATE INDEX idx_records_uid_datetime ON records(uid, datetime DESC);

-- 统计索引：覆盖 activity_type 用于聚合计算
CREATE INDEX idx_records_stats ON records(uid, activity_type);

-- 心情和地点：用于过滤查询
CREATE INDEX idx_records_mood ON records(mood) WHERE mood IS NOT NULL;
CREATE INDEX idx_records_location ON records(location) WHERE location IS NOT NULL;

-- 标签反向查询：用于查询"谁使用了这个体位/标签"
-- 注意：record_id 的索引已被主键覆盖，这里只需要 act_type
CREATE INDEX idx_record_acts_type ON record_acts(act_type);

-- 用户创建时间索引
CREATE INDEX idx_users_created ON users(created_at DESC);

-- ============================================
-- 触发器系统
-- ============================================

-- FTS 同步：插入
CREATE TRIGGER trg_records_ai_fts AFTER INSERT ON records
BEGIN
    INSERT INTO records_fts (record_id, uid, content)
    VALUES (
        NEW.id,
        NEW.uid,
        COALESCE(NEW.location, '') || ' ' || 
        COALESCE(NEW.mood, '') || ' ' || 
        COALESCE(NEW.activity_type, '') || ' ' ||
        COALESCE(NEW.stimulation, '') || ' ' ||
        COALESCE(NEW.partner_name, '') || ' ' ||
        COALESCE(NEW.sexual_position, '') || ' ' ||
        COALESCE(json_extract(NEW.data_json, '$.experience'), '')
    );
END;

-- FTS 同步：删除
-- 注意：不需要删除 record_acts，因为外键 CASCADE 会自动处理
CREATE TRIGGER trg_records_ad_fts AFTER DELETE ON records
BEGIN
    DELETE FROM records_fts WHERE record_id = OLD.id;
END;

-- FTS 同步：更新
CREATE TRIGGER trg_records_au_fts AFTER UPDATE ON records
BEGIN
    DELETE FROM records_fts WHERE record_id = OLD.id;
    INSERT INTO records_fts (record_id, uid, content)
    VALUES (
        NEW.id,
        NEW.uid,
        COALESCE(NEW.location, '') || ' ' || 
        COALESCE(NEW.mood, '') || ' ' || 
        COALESCE(NEW.activity_type, '') || ' ' ||
        COALESCE(NEW.stimulation, '') || ' ' ||
        COALESCE(NEW.partner_name, '') || ' ' ||
        COALESCE(NEW.sexual_position, '') || ' ' ||
        COALESCE(json_extract(NEW.data_json, '$.experience'), '')
    );
END;

-- 自动更新 updated_at 时间戳
CREATE TRIGGER trg_records_update_ts AFTER UPDATE ON records
BEGIN
    UPDATE records SET updated_at = datetime('now') WHERE id = NEW.id;
END;

CREATE TRIGGER trg_users_update_ts AFTER UPDATE ON users
BEGIN
    UPDATE users SET updated_at = datetime('now') WHERE uid = NEW.uid;
END;

-- ============================================
-- 视图定义
-- ============================================

-- 用户概览统计
CREATE VIEW v_user_stats AS
SELECT 
    u.uid,
    u.username,
    COUNT(r.id) as total_records,
    SUM(CASE WHEN r.activity_type = 'masturbation' THEN 1 ELSE 0 END) as masturbation_count,
    SUM(CASE WHEN r.activity_type = 'intercourse' THEN 1 ELSE 0 END) as intercourse_count,
    COALESCE(SUM(r.duration), 0) as total_duration,
    COALESCE(AVG(r.satisfaction), 0) as avg_satisfaction,
    MAX(r.datetime) as last_record_date
FROM users u
LEFT JOIN records r ON u.uid = r.uid
GROUP BY u.uid, u.username;