-- Reset
\i test/sql/common/reset.sql

-- Validate settings are changed
ALTER SYSTEM SET password_policy.min_uppercase_letter = 3;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.min_uppercase_letter');

ALTER SYSTEM SET password_policy.min_lowercase_letter = 5;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.min_lowercase_letter');

ALTER SYSTEM SET password_policy.min_special_chars = 4;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.min_special_chars');

ALTER SYSTEM SET password_policy.min_numbers = 5;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.min_numbers');

ALTER SYSTEM SET password_policy.min_password_len = 64;

SELECT pg_reload_conf();

SELECT current_setting('password_policy.min_password_len');

-- Reset
\i test/sql/common/reset.sql

;
