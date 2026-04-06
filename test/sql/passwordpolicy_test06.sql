CREATE EXTENSION IF NOT EXISTS passwordpolicy;

-- 1. Create a user and generate history
DROP USER IF EXISTS test_cleanup;
CREATE USER test_cleanup WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

-- Verify entry is in the history table
SELECT usename FROM passwordpolicy.accounts_password_history WHERE usename = 'test_cleanup';

-- 2. Drop the user
DROP USER test_cleanup;

-- 3. In a real scenario, the BGW would clean this up on next save.
-- We can simulate the BGW logic manually to ensure the query works.
DELETE FROM passwordpolicy.accounts_password_history h 
WHERE NOT EXISTS (SELECT 1 FROM pg_user u WHERE u.usename = h.usename);

SELECT count(*) FROM passwordpolicy.accounts_password_history WHERE usename = 'test_cleanup';
