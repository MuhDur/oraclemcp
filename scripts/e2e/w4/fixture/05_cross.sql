-- @statement
CREATE TABLE T_CROSS_&run_id (ID NUMBER(10) PRIMARY KEY, LABEL VARCHAR2(40))
-- @statement
GRANT SELECT ON T_CROSS_&run_id TO W4O_&run_id
