IF SUSER_ID('cerbos_user') IS NULL
CREATE LOGIN cerbos_user WITH PASSWORD = 'ChangeMe(1!!)';

GO

IF NOT EXISTS (
    SELECT [name]
        FROM sys.databases
        WHERE [name] = N'cerbos'
)
CREATE DATABASE cerbos;
GO

USE cerbos;

IF OBJECT_ID('[dbo].[policy]', 'U') IS NULL
CREATE TABLE [dbo].[policy] (
    id BIGINT PRIMARY KEY,
    kind VARCHAR(128) NOT NULL,
    name VARCHAR(1024) NOT NULL,
    version VARCHAR(128) NOT NULL,
    description NVARCHAR(MAX),
    disabled BIT default 'FALSE',
    definition VARBINARY(MAX));

IF OBJECT_ID('[dbo].[policy_dependency]', 'U') IS NULL
CREATE TABLE [dbo].[policy_dependency] (
    policy_id BIGINT NOT NULL,
    dependency_id BIGINT  NOT NULL,
    PRIMARY KEY (policy_id, dependency_id),
    FOREIGN KEY (policy_id) REFERENCES [policy](id) ON DELETE CASCADE);

IF OBJECT_ID('[dbo].[policy_revision]', 'U') IS NULL
CREATE TABLE [dbo].[policy_revision] (
    revision_id INT NOT NULL IDENTITY PRIMARY KEY,
    action VARCHAR(255) NOT NULL CHECK ([action] IN('INSERT', 'UPDATE', 'DELETE')),
    id BIGINT NOT NULL,
    kind VARCHAR(128),
    name VARCHAR(1024),
    version VARCHAR(128),
    description NVARCHAR(MAX),
    disabled BIT,
    definition VARBINARY(MAX),
    update_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);

IF OBJECT_ID('[dbo].[attr_schema_defs]', 'U') IS NULL
CREATE TABLE [dbo].[attr_schema_defs] (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    definition VARBINARY(MAX));

DROP TRIGGER IF EXISTS dbo.policy_on_insert;
DROP TRIGGER IF EXISTS dbo.policy_on_update;
DROP TRIGGER IF EXISTS dbo.policy_on_delete;

GO

USE cerbos;

IF USER_ID('cerbos_user') IS NULL
CREATE USER cerbos_user for LOGIN cerbos_user;

GRANT SELECT,INSERT,UPDATE,DELETE ON [dbo].[policy] TO cerbos_user;
GRANT SELECT,INSERT,UPDATE,DELETE ON dbo.attr_schema_defs TO cerbos_user;
GRANT SELECT,INSERT,UPDATE,DELETE ON dbo.policy_dependency TO cerbos_user;
GRANT SELECT,INSERT ON dbo.policy_revision TO cerbos_user;

GO

CREATE TRIGGER dbo.policy_on_insert ON dbo.[policy] AFTER INSERT
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.policy_revision(action, id, kind, name, version, description, disabled, definition)
    SELECT
        'INSERT', i.id, i.kind, i.name, i.version, i.description, i.disabled, i.definition
    FROM inserted i
END;

GO

CREATE TRIGGER dbo.policy_on_update ON dbo.[policy] AFTER UPDATE
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.policy_revision(action, id, kind, name, version, description, disabled, definition)
    SELECT
        'UPDATE', i.id, i.kind, i.name, i.version, i.description, i.disabled, i.definition
    FROM inserted i
END;

GO

CREATE TRIGGER dbo.policy_on_delete ON dbo.[policy] AFTER DELETE
AS
BEGIN
    SET NOCOUNT ON;
    INSERT INTO dbo.policy_revision(action, id, kind, name, version, description, disabled, definition)
    SELECT
        'DELETE', d.id, d.kind, d.name, d.version, d.description, d.disabled, d.definition
    FROM deleted d
END;

