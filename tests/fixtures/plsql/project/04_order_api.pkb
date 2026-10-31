CREATE OR REPLACE PACKAGE BODY app.order_api AS
  FUNCTION total(p_id NUMBER) RETURN NUMBER AS
    v_amount NUMBER;
  BEGIN
    SELECT amount INTO v_amount FROM app.orders WHERE id = p_id;
    RETURN v_amount;
  END;
END;
/
