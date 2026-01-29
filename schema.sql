DROP TABLE IF EXISTS records;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    uid TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

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
    data_json TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (uid) REFERENCES users(uid) ON DELETE CASCADE
);

CREATE INDEX idx_records_user_datetime ON records(uid, datetime DESC);
CREATE INDEX idx_records_stats ON records(uid, activity_type, duration);

-- 1. 创建全文检索虚拟表
CREATE VIRTUAL TABLE IF NOT EXISTS records_fts USING fts5(
    record_id UNINDEXED, 
    uid UNINDEXED, 
    content
);

-- 2. 创建触发器：插入时自动同步
DROP TRIGGER IF EXISTS trg_records_ai;
CREATE TRIGGER trg_records_ai AFTER INSERT ON records BEGIN
  INSERT INTO records_fts (record_id, uid, content)
  VALUES (
    new.id, 
    new.uid, 
    coalesce(new.location, '') || ' ' || 
    coalesce(new.mood, '') || ' ' || 
    coalesce(new.activity_type, '') || ' ' || 
    coalesce(json_extract(new.data_json, '$.experience'), '') || ' ' ||
    coalesce(json_extract(new.data_json, '$.acts'), '')
  );
END;

-- 3. 创建触发器：删除时自动同步
DROP TRIGGER IF EXISTS trg_records_ad;
CREATE TRIGGER trg_records_ad AFTER DELETE ON records BEGIN
  DELETE FROM records_fts WHERE record_id = old.id;
END;

-- 4. 创建触发器：更新时自动同步
DROP TRIGGER IF EXISTS trg_records_au;
CREATE TRIGGER trg_records_au AFTER UPDATE ON records BEGIN
  DELETE FROM records_fts WHERE record_id = old.id;
  INSERT INTO records_fts (record_id, uid, content)
  VALUES (
    new.id, 
    new.uid, 
    coalesce(new.location, '') || ' ' || 
    coalesce(new.mood, '') || ' ' || 
    coalesce(new.activity_type, '') || ' ' || 
    coalesce(json_extract(new.data_json, '$.experience'), '') || ' ' ||
    coalesce(json_extract(new.data_json, '$.acts'), '')
  );
END;