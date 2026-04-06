-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test06;

CREATE EXTENSION IF NOT EXISTS passwordpolicy;

-- Password history is populated
CREATE USER test06 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

-- Wait 1 minute for bgw flush
--SELECT pg_sleep(65);

-- Verify entry is in the history table
SELECT usename FROM passwordpolicy.accounts_password_history WHERE usename = 'test06';

-- 2. Drop the user
DROP USER test06;

-- Wait 1 minute for bgw flush
--SELECT pg_sleep(65);

-- Verify entry is not in the history table
SELECT count(*) FROM passwordpolicy.accounts_password_history WHERE usename = 'test06';

-- Reset
\i test/sql/common/reset.sql

DROP EXTENSION IF EXISTS passwordpolicy;

DROP USER IF EXISTS test06;

;