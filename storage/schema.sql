PRAGMA journal_mode=WAL;
PRAGMA foreing_keys=ON;
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  passhash TEXT NOT NULL,
  token TEXT,
  expiry TEXT
);
CREATE TABLE posts (
  user_id INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  content TEXT NOT NULL,
  PRIMARY KEY(user_id, created_at)
);
CREATE TABLE comments (
  user_id INTEGER NOT NULL REFERENCES users(id),
  post_id INTEGER NOT NULL REFERENCES posts(id),
  content TEXT NOT NULL,
  PRIMARY KEY(user_id, post_id)
);
