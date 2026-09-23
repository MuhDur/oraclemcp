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
-- @statement
BEGIN
    DBMS_FGA.ADD_POLICY(
        OBJECT_SCHEMA  => 'W4O_&run_id',
        OBJECT_NAME    => 'T_FGA_&run_id',
        POLICY_NAME    => 'P_FGA_&run_id',
        HANDLER_SCHEMA => 'W4O_&run_id',
        HANDLER_MODULE => 'PKG_W4_&run_id.FGA_HANDLER',
        STATEMENT_TYPES => 'SELECT'
    );
END;
