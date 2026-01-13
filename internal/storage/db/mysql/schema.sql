CREATE DATABASE IF NOT EXISTS cerbos CHARACTER SET utf8mb4;

USE cerbos;

CREATE TABLE IF NOT EXISTS policy (
    id BIGINT PRIMARY KEY,
    kind VARCHAR(128) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    version VARCHAR(128) NOT NULL,
    scope VARCHAR(512),
    description TEXT,
    disabled BOOLEAN default false,
    definition BLOB);

CREATE TABLE IF NOT EXISTS policy_dependency (
    policy_id BIGINT NOT NULL,
    dependency_id BIGINT NOT NULL,
    PRIMARY KEY (policy_id, dependency_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS policy_ancestor (
    policy_id BIGINT NOT NULL,
    ancestor_id BIGINT NOT NULL,
    PRIMARY KEY (policy_id, ancestor_id),
    FOREIGN KEY (policy_id) REFERENCES policy(id) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS policy_revision (
    revision_id INTEGER AUTO_INCREMENT PRIMARY KEY,
    action ENUM('INSERT', 'UPDATE', 'DELETE'),
    id BIGINT NOT NULL,
    kind VARCHAR(128),
    name VARCHAR(1024),
    version VARCHAR(128),
    scope VARCHAR(512),
    description TEXT,
    disabled BOOLEAN,
    definition BLOB,
    update_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);

CREATE TABLE IF NOT EXISTS attr_schema_defs (
    id VARCHAR(255) PRIMARY KEY,
    definition JSON);

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

CREATE USER IF NOT EXISTS cerbos_user IDENTIFIED BY 'changeme';
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy TO cerbos_user;
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.attr_schema_defs TO cerbos_user;
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy_dependency TO cerbos_user;
GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy_ancestor TO cerbos_user;
GRANT SELECT,INSERT,DELETE ON cerbos.policy_revision TO cerbos_user;
