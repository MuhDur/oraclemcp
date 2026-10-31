/**
 * Return a recorded order amount.
 * @param p_id Order identifier.
 * @returns The stored amount.
 */
CREATE OR REPLACE PACKAGE app.order_api AS
  FUNCTION total(p_id NUMBER) RETURN NUMBER;
END;
/
