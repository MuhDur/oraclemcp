-- hero_diff_dropcol/before — standalone procedure referencing customers.legacy_segment.
-- PLSQL-LAB-008 / §1.4 DROP COLUMN hero scenario (before state).
--
-- Third dependent unit so DROP COLUMN yields three distinct INVALID objects:
--   view + package body + procedure.
--
-- References customers.legacy_segment via %TYPE anchor and a direct SELECT.

CREATE OR REPLACE PROCEDURE proc_segment_summary(
    p_region IN VARCHAR2 DEFAULT NULL
)
IS
    v_seg    customers.legacy_segment%TYPE;
    v_count  NUMBER;
BEGIN
    FOR rec IN (
        SELECT legacy_segment AS seg_name, COUNT(*) AS cnt
        FROM   customers
        WHERE  (p_region IS NULL OR region = p_region)
          AND  legacy_segment IS NOT NULL
        GROUP BY legacy_segment
        ORDER BY COUNT(*) DESC
    ) LOOP
        v_seg   := rec.seg_name;
        v_count := rec.cnt;
        DBMS_OUTPUT.PUT_LINE('Segment: ' || v_seg || '  Count: ' || v_count);
    END LOOP;
EXCEPTION
    WHEN OTHERS THEN
        RAISE_APPLICATION_ERROR(-20020,
            'proc_segment_summary failed: ' || SQLERRM);
END proc_segment_summary;
