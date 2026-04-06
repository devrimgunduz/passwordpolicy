-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test01;

-- Fails
CREATE USER test01 WITH PASSWORD 'aaaa';

-- Fails
CREATE USER test01 WITH PASSWORD 'aaaaaaaaaaaaaaa';

-- Fails
CREATE USER test01 WITH PASSWORD 'aaaaaaaaaaaaaaa1234';

-- Fails
CREATE USER test01 WITH PASSWORD 'aaaaaaaaaaaaaaa#*#134';

-- Works
CREATE USER test01 WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

-- Reset
\i test/sql/common/reset.sql

DROP USER IF EXISTS test01;

;