-- ============================================================
-- AutoBB — Supabase Schema
-- Execute este SQL no SQL Editor do seu projeto Supabase
--
-- ATENÇÃO: A tabela `programs` JÁ EXISTE no seu banco com:
--   id int8, created_at timestamptz, program_name text, latest_scope_version_id text
-- NÃO recrie ela. Execute apenas as tabelas abaixo.
-- ============================================================

-- Habilitar extensão UUID
create extension if not exists "pgcrypto";

-- ─── Scans ───────────────────────────────────────────────────
-- Cada execução do scan4all por programa
create table if not exists scans (
  id            uuid primary key default gen_random_uuid(),
  program_name  text not null,           -- referencia programs.program_name
  domains       text[] not null default '{}',
  raw_output    text,
  status        text not null default 'completed'
    check (status in ('pending', 'running', 'completed', 'error')),
  created_at    timestamptz not null default now()
);

create index if not exists idx_scans_program_name on scans(program_name);
create index if not exists idx_scans_created      on scans(created_at desc);

-- ─── Vulnerabilities ─────────────────────────────────────────
-- Findings individuais parseados do output do scan4all
create table if not exists vulnerabilities (
  id            uuid primary key default gen_random_uuid(),
  scan_id       uuid not null references scans(id) on delete cascade,
  program_name  text not null,           -- referencia programs.program_name
  host          text,
  vuln_name     text,
  severity      text not null default 'info'
    check (severity in ('info', 'low', 'medium', 'high', 'critical')),
  details       text,
  created_at    timestamptz not null default now()
);

create index if not exists idx_vulns_severity     on vulnerabilities(severity);
create index if not exists idx_vulns_program_name on vulnerabilities(program_name);
create index if not exists idx_vulns_scan_id      on vulnerabilities(scan_id);

-- ─── RLS ─────────────────────────────────────────────────────
-- Use a service_role key no backend para bypassar RLS,
-- ou configure policies conforme necessário.
