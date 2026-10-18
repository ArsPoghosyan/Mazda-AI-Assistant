-- Requires askm6_migrator and askm6_app to exist.
-- Run as the database administrator.

BEGIN;

GRANT askm6_migrator TO CURRENT_USER WITH SET TRUE;
GRANT askm6_migrator TO CURRENT_USER WITH INHERIT FALSE;

CREATE SCHEMA app AUTHORIZATION askm6_migrator;

SET LOCAL ROLE askm6_migrator;

REVOKE ALL ON SCHEMA app FROM PUBLIC;
GRANT USAGE ON SCHEMA app TO askm6_app;

ALTER DEFAULT PRIVILEGES
    REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

COMMIT;