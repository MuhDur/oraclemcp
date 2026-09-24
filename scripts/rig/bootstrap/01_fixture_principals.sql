-- Rig L1 lane bootstrap (bead .9.2): the synthetic fixture principals the W4
-- suite and the D2 capability fixtures connect as. Idempotent: principals are
-- created when absent and their password and grants are (re)applied, so a rerun
-- never drops objects another run created. Run as SYSDBA inside the lane's PDB
-- with SQL*Plus substitution variables:
--   &1 fixture user   &2 fixture password   &3 proxy user   &4 proxy password
whenever sqlerror exit failure
set echo off feedback off heading off verify off define on

declare
  procedure ensure_user(p_user varchar2, p_password varchar2) is
    n pls_integer;
  begin
    select count(*) into n from dba_users where username = upper(p_user);
    if n = 0 then
      execute immediate 'create user ' || dbms_assert.simple_sql_name(p_user)
        || ' identified by "' || replace(p_password, '"', '') || '"';
    else
      execute immediate 'alter user ' || dbms_assert.simple_sql_name(p_user)
        || ' identified by "' || replace(p_password, '"', '') || '" account unlock';
    end if;
  end;
begin
  ensure_user('&1', '&2');
  ensure_user('&3', '&4');
end;
/

alter user &3 grant connect through &1;
grant create session to &3;

-- What the W4 fixture and the D2 capability fixtures need: own tables, views,
-- PL/SQL, triggers, sequences and types; the RLS and flashback packages; the
-- dictionary and V$ views the tools read. No write-implying ANY privilege.
grant
    create session,
    create table,
    create view,
    create procedure,
    create trigger,
    create sequence,
    create type,
    select any dictionary,
    change notification,
    unlimited tablespace
to &1;
grant execute on sys.dbms_rls to &1;
grant execute on sys.dbms_flashback to &1;
grant aq_administrator_role to &1;

exit
