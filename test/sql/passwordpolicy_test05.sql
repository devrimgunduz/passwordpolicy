-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test05;

-- Validate password history
-- ok
CREATE USER test05 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

SELECT pg_sleep(1);

-- Ok
ALTER USER test05 WITH PASSWORD 'ASWaaaaaaaaasdf#*#135';

SELECT pg_sleep(1);

-- Ok
ALTER USER test05 WITH PASSWORD 'ASWaaaaaaaaasdf#*#136';

SELECT pg_sleep(1);

-- Fails
ALTER USER test05 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

SELECT pg_sleep(1);

-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test05;

;