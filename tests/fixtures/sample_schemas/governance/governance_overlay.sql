-- D9 governance overlay for rig L2 — the layer the MIT sample schemas do not
-- provide.
--
-- oracle-samples/db-sample-schemas ships realistic SHAPE (tables, views, PL/SQL,
-- constraints) but no governance surface at all: no VPD/RLS, no proxy
-- authentication, no logoff auditing. Those are exactly what this server's
-- guard, lease and audit paths need to be exercised against, so they are layered
-- on top here rather than patched into the vendored SQL, which is never edited
-- in place (see ../PROVENANCE.md).
--
-- SYNTHETIC ONLY. Every identifier below is invented for this fixture. Nothing
-- here is derived from a real or field-test environment, and nothing here may
-- ever be.
--
-- Runs as the local lab's SYSDBA principal, after the vendored schemas load.
--
-- DELIBERATELY NOT DUPLICATED: scripts/rig/oracle_l1_privilege_matrix.sql (D4)
-- already owns the VPD-protected table ORACLEMCP_D4_OWNER.ORACLEMCP_D4_GUARDED,
-- its SELECT policy, and the two restricted principals ORACLEMCP_D4_NO_FLASHBACK
-- and ORACLEMCP_D4_CATALOG_BLIND. This file LAYERS on those names; it does not
-- recreate them. Run the D4 fixture first.

set echo off
set feedback off
whenever sqlerror exit failure

-- ---------------------------------------------------------------------------
-- 1. Synonym over a policy-protected base (D3).
--
-- The interesting property is that a synonym is only a name: selecting through
-- ORACLEMCP_D9_GUARDED_SYN must still be filtered by the VPD policy on the base
-- table. A guard that resolves object identity by NAME rather than by the object
-- the name reaches would see an unprotected synonym and wave it through, so this
-- fixture exists to make that mistake observable rather than theoretical.
-- ---------------------------------------------------------------------------
create or replace synonym ORACLEMCP_D4_OWNER.ORACLEMCP_D9_GUARDED_SYN
  for ORACLEMCP_D4_OWNER.ORACLEMCP_D4_GUARDED;

grant select on ORACLEMCP_D4_OWNER.ORACLEMCP_D4_GUARDED to ORACLEMCP_D4_CATALOG_BLIND;

-- ---------------------------------------------------------------------------
-- 2. Proxy CONNECT THROUGH pair.
--
-- The proxy authenticates; the target owns the privileges. The server's
-- proxy_auth profile connects as the proxy ON BEHALF OF the target, so the
-- effective schema must be the target's and never the proxy's.
-- ---------------------------------------------------------------------------
declare
  principal_missing exception;
  pragma exception_init(principal_missing, -1918);
begin
  for principal in (
    select 'ORACLEMCP_D9_PROXY' as name from dual
    union all select 'ORACLEMCP_D9_TARGET' from dual
  ) loop
    begin
      execute immediate 'drop user ' || principal.name || ' cascade';
    exception
      when principal_missing then null;
    end;
  end loop;
end;
/

create user ORACLEMCP_D9_TARGET identified by "D9_Governance_Test_42"
/
grant create session, create table, unlimited tablespace to ORACLEMCP_D9_TARGET
/
create user ORACLEMCP_D9_PROXY identified by "D9_Governance_Test_42"
/
grant create session to ORACLEMCP_D9_PROXY
/
-- The pair itself: the proxy may connect as the target, and only as the target.
alter user ORACLEMCP_D9_TARGET grant connect through ORACLEMCP_D9_PROXY
/

create table ORACLEMCP_D9_TARGET.ORACLEMCP_D9_OWNED_ROWS (
  id      number generated always as identity primary key,
  note    varchar2(64) not null
)
/
insert into ORACLEMCP_D9_TARGET.ORACLEMCP_D9_OWNED_ROWS (note)
  values ('reachable only through the proxy target schema')
/
commit
/

-- ---------------------------------------------------------------------------
-- 3. AFTER LOGOFF trigger (D7).
--
-- THE POINT OF THIS TRIGGER IS WHAT IT DOES NOT SEE.
--
-- `AFTER LOGOFF ON DATABASE` fires during a LOGICAL session close — the client
-- said goodbye and the server tore the session down in an orderly way. It does
-- NOT fire when a session dies abruptly: if the socket is dropped, the process
-- is killed, or the session is killed server-side, PMON reclaims the session
-- without ever running logoff triggers.
--
-- That asymmetry is the measurement. A row here means the server released the
-- session properly; the ABSENCE of a row after a disconnect means it merely
-- dropped the socket and left PMON to clean up. An operator cannot tell those
-- apart from the client side, which is precisely why the distinction is worth a
-- fixture.
--
-- Consequence for whoever writes the D7 lane: asserting a row appears proves a
-- clean close, but asserting nothing about the abrupt case proves nothing at
-- all. The lane needs BOTH halves — a clean close that writes a row, and an
-- abrupt termination that does not — or a server that never closes cleanly
-- would pass the clean half by accident on some other session.
-- ---------------------------------------------------------------------------
create table ORACLEMCP_D9_TARGET.ORACLEMCP_D9_LOGOFF_LOG (
  id            number generated always as identity primary key,
  session_id    number       not null,
  session_user  varchar2(128) not null,
  client_id     varchar2(128),
  module        varchar2(128),
  logged_at     timestamp with time zone default systimestamp not null
)
/
grant insert on ORACLEMCP_D9_TARGET.ORACLEMCP_D9_LOGOFF_LOG to public
/

-- A database-level trigger is owned by a schema, and Oracle requires the OWNER
-- to hold ADMINISTER DATABASE TRIGGER — the creating principal's privileges are
-- not enough. Creating this as SYSTEM (which already holds CREATE ANY TRIGGER
-- and ADMINISTER DATABASE TRIGGER) still fails ORA-01031 until the target has
-- them too, which is not obvious from the error text.
grant create trigger to ORACLEMCP_D9_TARGET
/
grant administer database trigger to ORACLEMCP_D9_TARGET
/

create or replace trigger ORACLEMCP_D9_TARGET.ORACLEMCP_D9_AFTER_LOGOFF
  before logoff on database
declare
  pragma autonomous_transaction;
begin
  -- Only sessions this rig owns, so the log stays readable on a lab instance
  -- that other lanes are also using.
  if sys_context('USERENV', 'SESSION_USER') like 'ORACLEMCP_%' then
    insert into ORACLEMCP_D9_TARGET.ORACLEMCP_D9_LOGOFF_LOG
      (session_id, session_user, client_id, module)
    values (
      to_number(sys_context('USERENV', 'SID')),
      sys_context('USERENV', 'SESSION_USER'),
      sys_context('USERENV', 'CLIENT_IDENTIFIER'),
      sys_context('USERENV', 'MODULE')
    );
    commit;
  end if;
exception
  -- A logoff trigger must never be able to block a logoff: an audit fixture
  -- that can wedge session teardown would be a worse bug than the one it
  -- measures.
  when others then
    null;
end;
/

-- `BEFORE LOGOFF` rather than `AFTER LOGOFF` is deliberate and is not a
-- weakening: Oracle runs the database-level logoff trigger while the session is
-- still able to execute SQL, so an AFTER-shaped trigger cannot insert its own
-- audit row. The clean-vs-abrupt asymmetry above is identical either way —
-- neither form runs when PMON reclaims a dead session.
