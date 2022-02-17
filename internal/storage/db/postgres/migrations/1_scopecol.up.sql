SET search_path TO cerbos;

CREATE TABLE IF NOT EXISTS policy_ancestor (
    policy_id BIGINT,
    ancestor_id BIGINT,
    PRIMARY KEY (policy_id, ancestor_id),
    FOREIGN KEY (policy_id) REFERENCES cerbos.policy(id) ON DELETE CASCADE
);

GRANT SELECT,INSERT,UPDATE,DELETE ON cerbos.policy_ancestor TO cerbos_user; 

CREATE OR REPLACE FUNCTION process_policy_audit() RETURNS TRIGGER AS $policy_audit$
    BEGIN
        IF (TG_OP = 'DELETE') THEN
            INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
            VALUES('DELETE', OLD.id, OLD.kind, OLD.name, OLD.version, OLD.scope, OLD.description, OLD.disabled, OLD.definition);
        ELSIF (TG_OP = 'UPDATE') THEN
            INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
            VALUES('UPDATE', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.scope, NEW.description, NEW.disabled, NEW.definition);
        ELSIF (TG_OP = 'INSERT') THEN
            INSERT INTO policy_revision(action, id, kind, name, version, scope, description, disabled, definition)
            VALUES('INSERT', NEW.id, NEW.kind, NEW.name, NEW.version, NEW.scope, NEW.description, NEW.disabled, NEW.definition);
        END IF;
        RETURN NULL; 
    END;
$policy_audit$ LANGUAGE plpgsql;
