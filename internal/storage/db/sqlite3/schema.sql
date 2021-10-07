PRAGMA foreign_keys = ON;

-- name: policy
CREATE TABLE IF NOT EXISTS policy (
    id UNSIGNED BIG INT NOT NULL PRIMARY KEY, 
    kind VARCHAR(128) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    version VARCHAR(128) NOT NULL,
    description TEXT,
    disabled BOOLEAN default false,
    definition BLOB
);

-- name: policy_dependency
CREATE TABLE IF NOT EXISTS policy_dependency (
    policy_id UNSIGNED BIG INT,
    dependency_id UNSIGNED BIG INT,
    PRIMARY KEY (policy_id, dependency_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE
);

-- name: policy_revision
CREATE TABLE IF NOT EXISTS policy_revision (
    revision_id INTEGER PRIMARY KEY AUTOINCREMENT,
    action VARCHAR(64),
    id UNSIGNED BIG INT,
    kind VARCHAR(128),
    name VARCHAR(1024),
    version VARCHAR(128),
    description TEXT,
    disabled BOOLEAN, 
    definition BLOB,
    update_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);


-- name: policy_on_insert
CREATE TRIGGER IF NOT EXISTS policy_on_insert AFTER INSERT ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
    VALUES("INSERT", new.id, new.kind, new.name, new.version, new.description, new.disabled, new.definition);
END;

-- name: policy_on_update
CREATE TRIGGER IF NOT EXISTS policy_on_update AFTER UPDATE ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
    VALUES("UPDATE", new.id, new.kind, new.name, new.version, new.description, new.disabled, new.definition);
END;

-- name: policy_on_delete
CREATE TRIGGER IF NOT EXISTS policy_on_delete AFTER DELETE ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
    VALUES("DELETE", old.id, old.kind, old.name, old.version, old.description, old.disabled, old.definition);
END;
