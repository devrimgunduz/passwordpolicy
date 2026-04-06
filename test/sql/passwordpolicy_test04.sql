-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test04;

-- Lower requirements to allow a simple word
ALTER SYSTEM SET password_policy.min_password_len = 6;

SELECT pg_reload_conf();

ALTER SYSTEM SET password_policy.min_uppercase_letter = 0;

SELECT pg_reload_conf();

ALTER SYSTEM SET password_policy.min_lowercase_letter = 0;

SELECT pg_reload_conf();

ALTER SYSTEM SET password_policy.min_special_chars = 0;

SELECT pg_reload_conf();

ALTER SYSTEM SET password_policy.min_numbers = 0;

SELECT pg_reload_conf();

-- Validate password using dictionary
ALTER SYSTEM SET password_policy.enable_dictionary_check = true;

SELECT pg_reload_conf();

-- Fails
CREATE USER test04 WITH PASSWORD 'password';

-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test04;
