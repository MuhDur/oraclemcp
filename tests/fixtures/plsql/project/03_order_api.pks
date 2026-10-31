/** Return the recorded order amount without changing stored data. */
CREATE OR REPLACE PACKAGE app.order_api AS
  FUNCTION total(p_id NUMBER) RETURN NUMBER;
END;
/
