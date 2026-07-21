-- D3 VPD/RLS fixture for Rig L1 — the field's top blocker, made reproducible.
--
-- Runs as the local lab's SYSDBA principal. Every identifier is synthetic;
-- nothing here refers to a customer or field-test identity.
--
-- WHY THIS EXISTS SEPARATELY FROM oracle_l1_privilege_matrix.sql (D4)
--
-- That fixture's policy function returns the literal predicate '1=1'. It proves
-- a policy can be ATTACHED, which is a different claim from a policy that
-- RESTRICTS: against a '1=1' policy, a gate that fails open and a gate that
-- works are indistinguishable, because no row is ever withheld. A round-3 field
-- test found the VPD gate failing open, and a fixture like that is how such a
-- defect survives to be found in the field rather than here.
--
-- So this policy genuinely withholds rows, and the lane asserts the withheld
-- rows are ABSENT FROM RESULTS — not that the query succeeded, not that a
-- policy is attached.
--
-- THE SHAPE BEING REPRODUCED
--
--   ORACLEMCP_D3_PROTECTED   4 rows: 2 PUBLIC, 2 RESTRICTED
--   policy predicate         classification = 'PUBLIC'   (a real restriction)
--   ORACLEMCP_D3_SIGHTED     SELECT on the table + SELECT_CATALOG_ROLE, so it
--                            can see the policy in ALL_POLICIES
--   ORACLEMCP_D3_BLIND       SELECT on the table and nothing else, so it cannot
--                            learn that a filter exists at all
--   ORACLEMCP_D3_PROTECTED_SYN  a synonym over the protected base: the name is
--                            not the object, and resolving identity by name
--                            must not lose the policy
--
-- The blind principal is the whole point. It receives a SHORT ANSWER with no
-- indication that anything was withheld: from the caller's side "these are all
-- the rows" and "these are the rows you are allowed to see" are the same
-- response. That silence is what A1a must convert into a typed refusal.

set echo off
set feedback off
whenever sqlerror exit failure

declare
  principal_missing exception;
  pragma exception_init(principal_missing, -1918);
begin
  for principal in (
    select 'ORACLEMCP_D3_OWNER' as name from dual
    union all select 'ORACLEMCP_D3_SIGHTED' from dual
    union all select 'ORACLEMCP_D3_BLIND' from dual
  ) loop
    begin
      execute immediate 'drop user ' || principal.name || ' cascade';
    exception
      when principal_missing then null;
    end;
  end loop;
end;
/

create user ORACLEMCP_D3_OWNER identified by "D3_Vpd_Test_42"
/
grant create session, create table, create procedure, unlimited tablespace
  to ORACLEMCP_D3_OWNER
/

create table ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED (
  id             number primary key,
  classification varchar2(16 char) not null,
  payload        varchar2(64 char) not null
)
/
insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED values (1, 'PUBLIC', 'visible row one')
/
insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED values (2, 'PUBLIC', 'visible row two')
/
-- The rows whose ABSENCE is the assertion. If a lane ever sees id 3 or 4
-- through the policy, the gate is failing open.
insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED values (3, 'RESTRICTED', 'withheld row three')
/
insert into ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED values (4, 'RESTRICTED', 'withheld row four')
/
commit
/

-- A REAL predicate. Contrast with D4's '1=1'.
create or replace function ORACLEMCP_D3_OWNER.ORACLEMCP_D3_VPD (
  schema_name varchar2,
  object_name varchar2
) return varchar2 authid definer as
begin
  return 'classification = ''PUBLIC''';
end;
/

begin
  dbms_rls.add_policy(
    object_schema   => 'ORACLEMCP_D3_OWNER',
    object_name     => 'ORACLEMCP_D3_PROTECTED',
    policy_name     => 'ORACLEMCP_D3_VPD',
    function_schema => 'ORACLEMCP_D3_OWNER',
    policy_function => 'ORACLEMCP_D3_VPD',
    -- SELECT only, deliberately. Policing INSERT too would make the fixture
    -- LOOK stronger while destroying the side channel this lane exists to
    -- expose: with reads filtered and writes unfiltered, a caller can still
    -- prove a hidden row exists by colliding with its primary key. That gap
    -- between "cannot read" and "cannot infer" is the finding, not a mistake.
    statement_types => 'SELECT'
  );
end;
/

-- The synonym: a second name for the same protected object.
create or replace synonym ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_SYN
  for ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED
/

-- The view is what makes the blind principal genuinely blind, and it was NOT
-- obvious: ALL_POLICIES lists the policies of every object ACCESSIBLE to the
-- caller, so a principal holding a direct SELECT on the protected table can
-- read the policy out of the catalog no matter what roles it lacks. Measured,
-- not assumed — the first version of this fixture withheld SELECT_CATALOG_ROLE
-- and the "blind" principal still reported one policy row.
--
-- Access through a view whose owner holds the base privileges is the shape that
-- actually blinds: the caller has rights on the view only, sees no base table
-- and no policy, and still receives VPD-filtered rows. That is the field's
-- silent-empty case — a short answer with nothing to explain it.
create or replace view ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V as
  select id, classification, payload from ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED
/

create user ORACLEMCP_D3_SIGHTED identified by "D3_Vpd_Test_42"
/
create user ORACLEMCP_D3_BLIND identified by "D3_Vpd_Test_42"
/
grant create session to ORACLEMCP_D3_SIGHTED
/
grant create session to ORACLEMCP_D3_BLIND
/
-- SIGHTED reaches the base object directly, so ALL_POLICIES will name the
-- policy for it (the A1e half).
grant select on ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED to ORACLEMCP_D3_SIGHTED
/
grant select on ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_SYN to ORACLEMCP_D3_SIGHTED
/

-- BLIND gets the VIEW and nothing else. No base table grant, no synonym grant:
-- one direct grant on the protected table would put the policy back in its
-- ALL_POLICIES and it would stop being blind.
grant select on ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V to ORACLEMCP_D3_BLIND
/

-- INSERT through the same view exists ONLY to exercise the side channel: a
-- unique-constraint violation on a primary key the caller cannot SELECT reveals
-- that the row is there. A caller that cannot read a row may still be able to
-- infer it, so the lane asserts on what can be INFERRED, not only on what can
-- be read. Granted on the view so BLIND still holds zero base-table privileges.
grant insert on ORACLEMCP_D3_OWNER.ORACLEMCP_D3_PROTECTED_V to ORACLEMCP_D3_BLIND
/

-- The sighted principal can enumerate policies; the blind one cannot. This is
-- the A1e half: doctor run as a sighted principal must be able to NAME the
-- policy, which is only possible when the catalog is visible.
grant select_catalog_role to ORACLEMCP_D3_SIGHTED
/
