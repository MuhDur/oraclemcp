-- `oraclemcp demo` seed: the parent/child subset of the W4 fixture
-- (scripts/e2e/w4/fixture/01_tables.sql). Each CREATE TABLE below must match
-- that fixture verbatim; demo::tests::seed_matches_fixture_subset checks it.
-- Data is synthetic. `&run_id` is replaced with the demo's fixed run id.
-- @statement
CREATE TABLE T_PARENT_&run_id (ID NUMBER(10) PRIMARY KEY, LABEL VARCHAR2(40))
-- @statement
CREATE TABLE T_CHILD_&run_id (
    ID NUMBER(10) PRIMARY KEY,
    PARENT_ID NUMBER(10) NOT NULL,
    CONSTRAINT FK_CHILD_&run_id FOREIGN KEY (PARENT_ID) REFERENCES T_PARENT_&run_id(ID)
)
-- @statement
INSERT INTO T_PARENT_&run_id (ID, LABEL) VALUES (1, 'parent-1')
-- @statement
INSERT INTO T_PARENT_&run_id (ID, LABEL) VALUES (2, 'parent-2')
-- @statement
INSERT INTO T_CHILD_&run_id (ID, PARENT_ID) VALUES (10, 1)
-- @statement
COMMIT
