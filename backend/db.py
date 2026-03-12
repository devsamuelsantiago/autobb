"""
AutoBB - Database Layer
Conexão com Supabase e funções de leitura/escrita de scans e vulnerabilidades.
"""

from __future__ import annotations

import os
from datetime import datetime
from supabase import create_client, Client
from dotenv import load_dotenv
from typing import Optional

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL e SUPABASE_KEY precisam estar definidos no .env")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# Nome real da tabela no Supabase
PROGRAMS_TABLE = "hackerone-programs"
SCANS_TABLE = "scans"
VULNS_TABLE = "vulnerabilities"


# ─── Programs ───────────────────────────────────────────────────────────────

def get_all_programs() -> list[dict]:
    """
    Busca todos os programas de bug bounty cadastrados no Supabase.
    Tabela real: hackerone-programs (id int8, created_at, program_name text, latest_scope_version_id text)
    """
    try:
        resp = supabase.table(PROGRAMS_TABLE).select("id, program_name, latest_scope_version_id, created_at").execute()
        return resp.data or []
    except Exception as e:
        print(f"[DB] Erro ao buscar programas: {e}")
        return []


# ─── Scans ───────────────────────────────────────────────────────────────────

def save_scan(program_name: str, domains: list, raw_output: str, status: str = "completed", scan_logs: list = None) -> dict:
    """
    Salva um scan executado no Supabase.
    Tabela: scans (id, program_name, domains, raw_output, status, created_at)
    raw_output é salvo como JSON estruturado: {"tool_output": "...", "logs": [...]}
    """
    import json as _json
    structured = _json.dumps({
        "tool_output": raw_output,
        "logs": scan_logs or [],
    })
    data = {
        "program_name": program_name,
        "domains": domains,
        "raw_output": structured,
        "status": status,
    }
    resp = supabase.table(SCANS_TABLE).insert(data).execute()
    return resp.data[0] if resp.data else {}


def get_all_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    try:
        resp = (
            supabase.table(SCANS_TABLE)
            .select("*")
            .order("created_at", desc=True)
            .range(offset, offset + limit - 1)
            .execute()
        )
        return resp.data or []
    except Exception as e:
        print(f"[DB] Erro ao buscar scans: {e}")
        return []


def get_scan_by_id(scan_id: str) -> Optional[dict]:
    try:
        resp = supabase.table(SCANS_TABLE).select("*").eq("id", scan_id).single().execute()
        return resp.data
    except Exception as e:
        print(f"[DB] Erro ao buscar scan {scan_id}: {e}")
        return None


def get_program_scans(program_name: str, limit: int = 20) -> list:
    """Retorna os últimos scans de um programa específico, incluindo logs embutidos."""
    import json as _json
    try:
        resp = (
            supabase.table(SCANS_TABLE)
            .select("id, program_name, domains, status, raw_output, created_at")
            .eq("program_name", program_name)
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        rows = resp.data or []
        # Extrai logs do raw_output estruturado
        for row in rows:
            raw = row.get("raw_output") or ""
            try:
                parsed = _json.loads(raw)
                row["logs"] = parsed.get("logs", [])
            except Exception:
                # raw_output antigo (texto puro) — sem logs estruturados
                row["logs"] = []
            row.pop("raw_output", None)
        return rows
    except Exception as e:
        print(f"[DB] Erro ao buscar scans de '{program_name}': {e}")
        return []


def get_program_vulns(program_name: str, limit: int = 200) -> list:
    """Retorna as vulnerabilidades (low/medium/high/critical) de um programa específico."""
    try:
        resp = (
            supabase.table(VULNS_TABLE)
            .select("id, scan_id, host, vuln_name, severity, details, created_at")
            .eq("program_name", program_name)
            .in_("severity", ["info", "low", "medium", "high", "critical"])
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return resp.data or []
    except Exception as e:
        print(f"[DB] Erro ao buscar vulns de '{program_name}': {e}")
        return []


# ─── Vulnerabilities ─────────────────────────────────────────────────────────

def save_vulnerabilities(scan_id: str, program_name: str, vulns: list[dict]) -> None:
    if not vulns:
        return
    rows = []
    for v in vulns:
        rows.append({
            "scan_id": scan_id,
            "program_name": program_name,
            "host": v.get("host", ""),
            "vuln_name": v.get("vuln_name", ""),
            "severity": v.get("severity", "info").lower(),
            "details": v.get("details", ""),
        })
    supabase.table(VULNS_TABLE).insert(rows).execute()




def get_last_scan_per_program() -> dict:
    """
    Retorna dict {program_name: created_at} com o scan mais recente de cada programa.
    Usa paginação para cobrir todos os registros sem timeout.
    """
    seen: dict = {}
    try:
        page_size = 1000
        offset = 0
        while True:
            resp = (
                supabase.table(SCANS_TABLE)
                .select("program_name, created_at")
                .order("created_at", desc=True)
                .range(offset, offset + page_size - 1)
                .execute()
            )
            rows = resp.data or []
            if not rows:
                break
            for row in rows:
                name = row.get("program_name")
                if name and name not in seen:
                    seen[name] = row.get("created_at")
            if len(rows) < page_size:
                break
            offset += page_size
    except Exception as e:
        print(f"[DB] Erro ao buscar last scan por programa: {e}")
    return seen

def get_recently_scanned(within_hours: int = 6) -> set:
    """
    Retorna o set de program_names que já tiveram scan nas últimas `within_hours` horas.
    Usado pelo worker para não repetir scans no mesmo ciclo.
    """
    from datetime import timezone
    cutoff = (datetime.utcnow().replace(tzinfo=timezone.utc)
              .isoformat(timespec='seconds'))
    # Calcula cutoff subtraindo within_hours
    from datetime import timedelta
    cutoff_dt = datetime.utcnow().replace(tzinfo=timezone.utc) - timedelta(hours=within_hours)
    cutoff = cutoff_dt.isoformat(timespec='seconds')
    try:
        resp = (
            supabase.table(SCANS_TABLE)
            .select("program_name")
            .gte("created_at", cutoff)
            .execute()
        )
        return {row["program_name"] for row in (resp.data or [])}
    except Exception as e:
        print(f"[DB] Erro ao buscar scans recentes: {e}")
        return set()


def get_vuln_stats() -> dict:
    """Retorna contagem de vulns por severidade (low/medium/high/critical)."""
    severities = ["info", "low", "medium", "high", "critical"]
    result = {sev: 0 for sev in severities}
    try:
        resp = (
            supabase.table(VULNS_TABLE)
            .select("severity")
            .in_("severity", severities)
            .execute()
        )
        for row in (resp.data or []):
            sev = row.get("severity", "")
            if sev in result:
                result[sev] += 1
    except Exception as e:
        print(f"[DB] Erro ao buscar stats de vulns (tabela criada?): {e}")
    return result


def get_programs_stats() -> list:
    """Retorna vulnerabilidades (low/medium/high/critical) agrupadas por programa."""
    try:
        resp = (
            supabase.table(VULNS_TABLE)
            .select("program_name, severity")
            .in_("severity", ["info", "low", "medium", "high", "critical"])
            .execute()
        )
        rows = resp.data or []
    except Exception as e:
        print(f"[DB] Erro ao buscar program stats (tabela criada?): {e}")
        return []

    stats: dict = {}
    for row in rows:
        name = row.get("program_name", "unknown")
        sev = row.get("severity", "")
        if name not in stats:
            stats[name] = {"program": name, "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        if sev in stats[name]:
            stats[name][sev] += 1
    return list(stats.values())
