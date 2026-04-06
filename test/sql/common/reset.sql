-- Reset
ALTER SYSTEM RESET password_policy.min_uppercase_letter;

ALTER SYSTEM RESET password_policy.min_lowercase_letter;

ALTER SYSTEM RESET password_policy.min_special_chars;

ALTER SYSTEM RESET password_policy.min_numbers;

ALTER SYSTEM RESET password_policy.min_password_len;

ALTER SYSTEM RESET password_policy.require_validuntil;

ALTER SYSTEM RESET password_policy.enable_dictionary_check;

SELECT pg_reload_conf();