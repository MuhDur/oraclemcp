-- Deterministic D2 capability fixtures for the existing Rig L1 Oracle lanes.
--
-- This script runs as the throwaway PYO_TEST_MAIN_USER after the driver's
-- bootstrap has recreated that user.  It deliberately owns only the
-- ORACLEMCP_CAP_* namespace, so re-running it is idempotent and cannot affect
-- a neighbouring live-test fixture.
whenever sqlerror exit failure
set echo off feedback off heading off verify off

begin
  for object_name in (
    select object_name
      from user_objects
     where object_name in (
       'ORACLEMCP_CAP_TYPED',
       'ORACLEMCP_CAP_LOB',
       'ORACLEMCP_CAP_STMT_CACHE',
       'ORACLEMCP_CAP_TPC',
       'ORACLEMCP_CAP_VECTOR',
       'ORACLEMCP_CAP_REFCURSOR',
       'ORACLEMCP_CAP_OUTPUT'
     )
  ) loop
    begin
      if object_name.object_name in ('ORACLEMCP_CAP_REFCURSOR', 'ORACLEMCP_CAP_OUTPUT') then
        execute immediate 'drop package ' || object_name.object_name;
      else
        execute immediate 'drop table ' || object_name.object_name || ' purge';
      end if;
    exception
      when others then
        if sqlcode != -4043 then
          raise;
        end if;
    end;
  end loop;
end;
/

create table ORACLEMCP_CAP_TYPED (
  id number primary key,
  number_value number(12, 3) not null,
  date_value date not null,
  timestamptz_value timestamp with time zone not null,
  raw_value raw(4) not null,
  text_value varchar2(64 char) not null
)
/
insert into ORACLEMCP_CAP_TYPED values (
  1,
  42.125,
  date '2024-02-29',
  to_timestamp_tz('2024-02-29 12:34:56 +02:00', 'YYYY-MM-DD HH24:MI:SS TZH:TZM'),
  hextoraw('DEADBEEF'),
  'd2 typed row'
)
/

create table ORACLEMCP_CAP_LOB (
  id number primary key,
  text_value clob not null,
  blob_value blob not null
)
/
insert into ORACLEMCP_CAP_LOB values (
  1,
  to_clob(rpad('L', 96, 'L')),
  to_blob(hextoraw('DEADBEEFCAFEBABE'))
)
/

create or replace package ORACLEMCP_CAP_REFCURSOR as
  procedure open_typed_rows(out_rows out sys_refcursor);
end ORACLEMCP_CAP_REFCURSOR;
/
create or replace package body ORACLEMCP_CAP_REFCURSOR as
  procedure open_typed_rows(out_rows out sys_refcursor) is
  begin
    open out_rows for
      select id, number_value, text_value
        from ORACLEMCP_CAP_TYPED
       order by id;
  end open_typed_rows;
end ORACLEMCP_CAP_REFCURSOR;
/

create or replace package ORACLEMCP_CAP_OUTPUT as
  procedure emit_fixture_line;
end ORACLEMCP_CAP_OUTPUT;
/
create or replace package body ORACLEMCP_CAP_OUTPUT as
  procedure emit_fixture_line is
  begin
    dbms_output.put_line('oraclemcp-d2-output');
  end emit_fixture_line;
end ORACLEMCP_CAP_OUTPUT;
/

create table ORACLEMCP_CAP_STMT_CACHE (
  cache_key number primary key,
  cache_value varchar2(32 char) not null
)
/
insert into ORACLEMCP_CAP_STMT_CACHE values (1, 'first cached row')
/
insert into ORACLEMCP_CAP_STMT_CACHE values (2, 'second cached row')
/

-- The server has no public XA/TPC tool.  Keep a deterministic transaction
-- target nevertheless: this lets a future surface prove an explicit
-- unsupported response rather than treating absent XA/TPC coverage as green.
create table ORACLEMCP_CAP_TPC (
  branch_id varchar2(32 char) primary key,
  state varchar2(16 char) not null
)
/
insert into ORACLEMCP_CAP_TPC values ('d2-local-only', 'unprepared')
/

declare
  l_major pls_integer;
  l_collection soda_collection_t;
begin
  select to_number(regexp_substr(version, '^[0-9]+'))
    into l_major
    from v$instance;

  if l_major >= 23 then
    begin
      dbms_soda.drop_collection('ORACLEMCP_CAP_SODA');
    exception
      when others then
        null;
    end;
    l_collection := dbms_soda.create_collection('ORACLEMCP_CAP_SODA');
    execute immediate
      'create table ORACLEMCP_CAP_VECTOR (' ||
      'id number primary key, embedding vector(3, float32) not null)';
    execute immediate
      'insert into ORACLEMCP_CAP_VECTOR values (1, ''[1,2,3]'')';
  end if;
end;
/

commit
/
exit
