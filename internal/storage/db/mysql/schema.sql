CREATE DATABASE IF NOT EXISTS cerbos;

USE cerbos;

CREATE TABLE IF NOT EXISTS policy (
    id BIGINT PRIMARY KEY, 
    kind VARCHAR(128) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    version VARCHAR(128) NOT NULL,
    description TEXT,
    disabled BOOLEAN default false,
    definition BLOB);

CREATE TABLE IF NOT EXISTS policy_dependency (
    policy_id BIGINT NOT NULL,
    dependency_id BIGINT UNSIGNED NOT NULL,
    PRIMARY KEY (policy_id, dependency_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS policy_revision (
    revision_id INTEGER AUTO_INCREMENT PRIMARY KEY,
    action ENUM('INSERT', 'UPDATE', 'DELETE'),
    id BIGINT NOT NULL,
    kind VARCHAR(128),
    name VARCHAR(1024),
    version VARCHAR(128),
    description TEXT,
    disabled BOOLEAN, 
    definition BLOB,
    update_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

DROP TRIGGER IF EXISTS policy_on_insert;

CREATE TRIGGER policy_on_insert AFTER INSERT ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
VALUES('INSERT', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.description, NEW.disabled, NEW.definition);

DROP TRIGGER IF EXISTS policy_on_update;

CREATE TRIGGER policy_on_update AFTER UPDATE ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
VALUES('UPDATE', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.description, NEW.disabled, NEW.definition);

DROP TRIGGER IF EXISTS policy_on_delete;

CREATE TRIGGER policy_on_delete AFTER DELETE ON policy 
FOR EACH ROW
INSERT INTO policy_revision(action, id, kind, name, version, description, disabled, definition)
VALUES('DELETE', OLD.id, OLD.kind, OLD.name, OLD.version, OLD.description, OLD.disabled, OLD.definition);

CREATE USER IF NOT EXISTS cerbos_user IDENTIFIED WITH mysql_native_password BY 'changeme';
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy TO cerbos_user; 
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy_dependency TO cerbos_user; 
GRANT SELECT,INSERT ON cerbos.policy_revision TO cerbos_user; 
