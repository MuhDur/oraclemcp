-- @statement
BEGIN
    DBMS_RLS.ADD_POLICY(
        OBJECT_SCHEMA   => 'W4O_&run_id',
        OBJECT_NAME     => 'T_SECURE_&run_id',
        POLICY_NAME     => 'P_SECURE_&run_id',
        FUNCTION_SCHEMA => 'W4O_&run_id',
        POLICY_FUNCTION => 'PKG_W4_&run_id.POLICY_FN',
        STATEMENT_TYPES => 'SELECT'
    );
END;
