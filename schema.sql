CREATE TABLE file (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  resource TEXT UNIQUE NOT NULL
);
CREATE TABLE url (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  resource TEXT UNIQUE NOT NULL
);