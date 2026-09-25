-- hero_diff_dropcol/before — package body for customer reporting.
-- PLSQL-LAB-008 / §1.4 DROP COLUMN hero scenario (before state).
--
-- References customers.legacy_segment in three places:
--   1. get_customers_by_segment: WHERE customers.legacy_segment = p_segment
--   2. get_segment_summary: GROUP BY customers.legacy_segment
--   3. audit_segment_access: customers.legacy_segment%TYPE anchor + SELECT
--
-- After DROP COLUMN customers.legacy_segment, this body becomes INVALID.

CREATE OR REPLACE PACKAGE BODY pkg_customer_report
AS

    FUNCTION get_customers_by_segment(
        p_segment IN VARCHAR2
    ) RETURN SYS_REFCURSOR
    IS
        v_cur SYS_REFCURSOR;
    BEGIN
        OPEN v_cur FOR
            SELECT customer_id, customer_name, email, region, legacy_segment
            FROM   customers
            WHERE  legacy_segment = p_segment
            ORDER BY customer_name;
        RETURN v_cur;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE_APPLICATION_ERROR(-20010,
                'pkg_customer_report.get_customers_by_segment failed: ' || SQLERRM);
    END get_customers_by_segment;

    FUNCTION get_segment_summary RETURN t_segment_tab
    IS
        v_result t_segment_tab;
        v_idx    PLS_INTEGER := 1;

        CURSOR c_summary IS
            SELECT legacy_segment AS seg_name, COUNT(*) AS seg_count, region AS seg_region
            FROM   customers
            WHERE  legacy_segment IS NOT NULL
            GROUP BY legacy_segment, region
            ORDER BY legacy_segment, region;
    BEGIN
        FOR rec IN c_summary LOOP
            v_result(v_idx).segment_name   := rec.seg_name;
            v_result(v_idx).customer_count := rec.seg_count;
            v_result(v_idx).region         := rec.seg_region;
            v_idx := v_idx + 1;
        END LOOP;
        RETURN v_result;
    EXCEPTION
        WHEN OTHERS THEN
            RAISE_APPLICATION_ERROR(-20011,
                'pkg_customer_report.get_segment_summary failed: ' || SQLERRM);
    END get_segment_summary;

    PROCEDURE audit_segment_access(
        p_customer_id IN NUMBER,
        p_segment     IN VARCHAR2
    )
    IS
        v_current_segment customers.legacy_segment%TYPE;
    BEGIN
        SELECT legacy_segment
        INTO   v_current_segment
        FROM   customers
        WHERE  customer_id = p_customer_id;

        IF v_current_segment != p_segment THEN
            RAISE_APPLICATION_ERROR(-20012,
                'Segment mismatch for customer ' || p_customer_id ||
                ': stored=' || v_current_segment || ', supplied=' || p_segment);
        END IF;
    EXCEPTION
        WHEN NO_DATA_FOUND THEN
            RAISE_APPLICATION_ERROR(-20013,
                'Customer not found: ' || p_customer_id);
    END audit_segment_access;

END pkg_customer_report;
