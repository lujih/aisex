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