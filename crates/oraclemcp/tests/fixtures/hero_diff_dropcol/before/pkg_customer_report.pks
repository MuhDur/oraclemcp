-- hero_diff_dropcol/before — package spec for customer reporting.
-- PLSQL-LAB-008 / §1.4 DROP COLUMN hero scenario (before state).
--
-- The spec itself does not reference legacy_segment directly.
-- The body (pkg_customer_report.pkb) does; after DROP COLUMN the body becomes INVALID.

CREATE OR REPLACE PACKAGE pkg_customer_report
AS
    -- Summary record type returned by get_segment_summary.
    TYPE t_segment_rec IS RECORD (
        segment_name   VARCHAR2(30),
        customer_count NUMBER(10),
        region         VARCHAR2(60)
    );

    TYPE t_segment_tab IS TABLE OF t_segment_rec INDEX BY PLS_INTEGER;

    -- Return all customers in a given legacy_segment tier.
    FUNCTION get_customers_by_segment(
        p_segment IN VARCHAR2
    ) RETURN SYS_REFCURSOR;

    -- Return a summary of customer counts grouped by legacy_segment + region.
    FUNCTION get_segment_summary RETURN t_segment_tab;

    -- Log a segment audit event referencing the legacy_segment value.
    PROCEDURE audit_segment_access(
        p_customer_id IN NUMBER,
        p_segment     IN VARCHAR2
    );

END pkg_customer_report;
