PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS rule_defs (
    id   UNSIGNED BIG INT NOT NULL PRIMARY KEY,
    origin_fqn TEXT NOT NULL,
    definition BLOB NOT NULL,
);

CREATE TABLE IF NOT EXISTS rule_index (
    id UNSIGNED BIG INT NOT NULL PRIMARY KEY,
    rule_id BIG INT NOT NULL,
    name TEXT NOT NULL,
    resource TEXT NOT NULL,
    role TEXT NOT NULL,
    action TEXT NOT NULL,
    effect TEXT NOT NULL,
    scope TEXT,
    scope_permissions TEXT,
    version TEXT,
    principal TEXT,
    FOREIGN KEY (rule_id) REFERENCES rule_defs(id) ON DELETE CASCADE
);


