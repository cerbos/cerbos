USE cerbos;

CREATE TABLE IF NOT EXISTS policy_ancestor (
    policy_id BIGINT NOT NULL,
    ancestor_id BIGINT NOT NULL,
    PRIMARY KEY (policy_id, ancestor_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE);

GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy_ancestor TO cerbos_user;

ALTER TABLE policy ADD COLUMN scope VARCHAR(512);  

ALTER TABLE policy_revision ADD COLUMN scope VARCHAR(512);  

DROP TRIGGER IF EXISTS policy_on_insert;

CREATE TRIGGER policy_on_insert AFTER INSERT ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
VALUES('INSERT', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.scope, NEW.description, NEW.disabled, NEW.definition);

DROP TRIGGER IF EXISTS policy_on_update;

CREATE TRIGGER policy_on_update AFTER UPDATE ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
VALUES('UPDATE', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.scope, NEW.description, NEW.disabled, NEW.definition);

DROP TRIGGER IF EXISTS policy_on_delete;

CREATE TRIGGER policy_on_delete AFTER DELETE ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
VALUES('DELETE', OLD.id, OLD.kind, OLD.name, OLD.version, OLD.scope, OLD.description, OLD.disabled, OLD.definition);
