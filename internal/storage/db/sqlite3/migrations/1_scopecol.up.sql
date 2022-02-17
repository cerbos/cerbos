CREATE TABLE IF NOT EXISTS policy_ancestor (
    policy_id UNSIGNED BIG INT,
    ancestor_id UNSIGNED BIG INT,
    PRIMARY KEY (policy_id, ancestor_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE
);

ALTER TABLE policy ADD COLUMN scope VARCHAR(512);  

ALTER TABLE policy_revision ADD COLUMN scope VARCHAR(512);  

DROP TRIGGER IF EXISTS policy_on_insert;

CREATE TRIGGER policy_on_insert AFTER INSERT ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
    VALUES("INSERT", new.id, new.kind, new.name, new.version, new.scope, new.description, new.disabled, new.definition);
END;

DROP TRIGGER IF EXISTS policy_on_update;

CREATE TRIGGER policy_on_update AFTER UPDATE ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
    VALUES("UPDATE", new.id, new.kind, new.name, new.version, new.scope, new.description, new.disabled, new.definition);
END;

DROP TRIGGER IF EXISTS policy_on_delete;

CREATE TRIGGER policy_on_delete AFTER DELETE ON policy 
BEGIN
    INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
    VALUES("DELETE", old.id, old.kind, old.name, old.version, old.scope, old.description, old.disabled, old.definition);
END;
