-- D4 privilege-matrix fixture for Rig L1.
--
-- This runs only as the local lab's SYSDBA principal.  It recreates three
-- names wholly owned by this fixture, then proves the catalog target has both
-- a SELECT VPD policy and a virtual column before any restricted principal is
-- used.  Nothing here refers to a customer or field-test identity.
whenever sqlerror exit failure
set echo off feedback off heading off verify off serveroutput on size 1000000

begin
  for principal in (
    select 'ORACLEMCP_D4_NO_FLASHBACK' as name from dual union all
    select 'ORACLEMCP_D4_CATALOG_BLIND' from dual union all
    select 'ORACLEMCP_D4_OWNER' from dual
  ) loop
    begin
      execute immediate 'drop user ' || principal.name || ' cascade';
    exception
      when others then
        if sqlcode != -1918 then
          raise;
        end if;
    end;
  end loop;
end;
/

create user ORACLEMCP_D4_OWNER identified by "D4_Privilege_Test_42"
/
grant create session, create table, create procedure, unlimited tablespace to ORACLEMCP_D4_OWNER
/

create table ORACLEMCP_D4_OWNER.ORACLEMCP_D4_GUARDED (
  id number primary key,
  payload varchar2(32 char) not null,
  derived_marker number generated always as (id + 1) virtual
)
/
insert into ORACLEMCP_D4_OWNER.ORACLEMCP_D4_GUARDED (id, payload) values (1, 'd4 fixture row')
/

create or replace function ORACLEMCP_D4_OWNER.ORACLEMCP_D4_VPD (
  schema_name varchar2,
  object_name varchar2
) return varchar2 authid definer as
begin
  return '1=1';
end;
/

begin
  dbms_rls.add_policy(
    object_schema => 'ORACLEMCP_D4_OWNER',
    object_name => 'ORACLEMCP_D4_GUARDED',
    policy_name => 'ORACLEMCP_D4_VPD',
    function_schema => 'ORACLEMCP_D4_OWNER',
    policy_function => 'ORACLEMCP_D4_VPD',
    statement_types => 'SELECT'
  );
end;
/

create user ORACLEMCP_D4_NO_FLASHBACK identified by "D4_Privilege_Test_42"
/
create user ORACLEMCP_D4_CATALOG_BLIND identified by "D4_Privilege_Test_42"
/

-- The first principal must reach Oracle with no direct DBMS_FLASHBACK grant;
-- the second may create a session but has no object or catalog role grant.
grant create session to ORACLEMCP_D4_NO_FLASHBACK
/
grant create session to ORACLEMCP_D4_CATALOG_BLIND
/

declare
  policy_count pls_integer;
  virtual_count pls_integer;
begin
  select count(*) into policy_count
    from dba_policies
   where object_owner = 'ORACLEMCP_D4_OWNER'
     and object_name = 'ORACLEMCP_D4_GUARDED'
     and policy_name = 'ORACLEMCP_D4_VPD'
     and enable = 'YES'
     and sel = 'YES';
  select count(*) into virtual_count
    from dba_tab_cols
   where owner = 'ORACLEMCP_D4_OWNER'
     and table_name = 'ORACLEMCP_D4_GUARDED'
     and column_name = 'DERIVED_MARKER'
     and virtual_column = 'YES';
  if policy_count != 1 or virtual_count != 1 then
    raise_application_error(
      -20040,
      'D4 catalog target must have exactly one enabled SELECT policy and one virtual column'
    );
  end if;
end;
/

select 'oraclemcp-d4-catalog-object-id=' || object_id
  from dba_objects
 where owner = 'ORACLEMCP_D4_OWNER'
   and object_name = 'ORACLEMCP_D4_GUARDED'
   and object_type = 'TABLE'
/

commit
/
prompt oraclemcp-d4-privilege-fixture-ready
exit
