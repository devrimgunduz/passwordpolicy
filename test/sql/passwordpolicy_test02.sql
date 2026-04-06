-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test02;

-- Validate that the user requires VALID
ALTER SYSTEM SET password_policy.require_validuntil = true;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.require_validuntil');

-- Fails
CREATE USER test02 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

-- Works
CREATE USER test02 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134' VALID UNTIL '2099-12-31';

-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test02;

;
