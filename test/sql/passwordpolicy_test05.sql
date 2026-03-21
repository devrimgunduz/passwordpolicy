CREATE EXTENSION IF NOT EXISTS passwordpolicy;

DROP USER IF EXISTS test_history;

CREATE USER test_history WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

ALTER USER test_history WITH PASSWORD 'ASWaaaaaaaaasdf#*#135';

ALTER USER test_history WITH PASSWORD 'ASWaaaaaaaaasdf#*#136';

ALTER USER test_history WITH PASSWORD 'ASWaaaaaaaaasdf#*#134';

DROP USER IF EXISTS test_history;

DROP EXTENSION IF EXISTS passwordpolicy;

;