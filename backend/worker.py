"""
AutoBB - Worker
Loop principal que:
  1. Busca programas ativos do Supabase
  2. Pega o escopo de cada programa via HackerOne GraphQL
  3. Escreve a lista de domínios em arquivo temporário
  4. Executa: scan4all -host host1.com,host2.com -v
  5. Faz parse do output e salva no Supabase
"""

from __future__ import annotations

import os
import json
import shutil
import time
import tempfile
import subprocess
import logging
import asyncio
import threading
import urllib.request
import urllib.error
import http.client
import ssl
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, List, Dict
from dotenv import load_dotenv

from db import get_all_programs, save_scan, save_vulnerabilities, get_recently_scanned
from hackerone import get_program_scope
from parser import parse_scan4all_output

# Carrega .env da raiz do repo (um nível acima de backend/)
_root_env = os.path.join(os.path.dirname(__file__), "..", ".env")
load_dotenv(dotenv_path=_root_env)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("autobb.worker")

# Caminho do binário scan4all (pode ser sobrescrito via env)
SCAN4ALL_BIN = os.getenv("SCAN4ALL_BIN", "scan4all")

# Caminho do subfinder
SUBFINDER_BIN = os.getenv("SUBFINDER_BIN", "subfinder")

# Timeout do subfinder por wildcard (segundos)
SUBFINDER_TIMEOUT = int(os.getenv("SUBFINDER_TIMEOUT", "120"))

# Intervalo entre ciclos completos (em segundos), default 6 horas
WORKER_INTERVAL = int(os.getenv("WORKER_INTERVAL", str(6 * 60 * 60)))

# Timeout do scan por programa (segundos), default 2 horas
SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", str(2 * 60 * 60)))

# Programas scaneados em paralelo (recomendado: 3-5, limitado por CPU/RAM)
PARALLEL_WORKERS = max(1, min(int(os.getenv("PARALLEL_WORKERS", "3")), 10))

# Horas mínimas entre re-scans do mesmo programa
RESCAN_HOURS = int(os.getenv("RESCAN_HOURS", "24"))

# Discord webhook URL (opcional)
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK", "")

# Flag global: True quando o usuário pediu cancelamento (Ctrl+C)
_SHUTDOWN = threading.Event()

# Cores por severidade (Discord embed colors)
_SEV_COLOR = {
    "critical": 0xFF0000,
    "high":     0xFF6600,
    "medium":   0xFFCC00,
    "low":      0x00AAFF,
    "info":     0x808080,
}


def _discord_post(payload: dict) -> None:
    """Envia um payload JSON ao Discord webhook via http.client (fire-and-forget)."""
    if not DISCORD_WEBHOOK:
        return
    try:
        body = json.dumps(payload).encode("utf-8")
        # Parseia a URL manualmente para usar http.client diretamente
        # discord.com/api/webhooks/...
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection("discord.com", timeout=10, context=ctx)
        path = DISCORD_WEBHOOK.replace("https://discord.com", "")
        conn.request(
            "POST",
            path,
            body=body,
            headers={"Content-Type": "application/json", "User-Agent": "AutoBB/1.0"},
        )
        resp = conn.getresponse()
        resp.read()  # drena o corpo
        conn.close()
        if resp.status not in (200, 204):
            log.warning(f"Discord webhook retornou: {resp.status} {resp.reason}")
    except Exception as exc:
        log.warning(f"Discord webhook falhou: {exc}")


def discord_notify_vuln(program_name: str, vuln: dict) -> None:
    """Manda embed no Discord para uma vulnerabilidade encontrada."""
    sev      = vuln.get("severity", "info").lower()
    color    = _SEV_COLOR.get(sev, 0x808080)
    host     = vuln.get("host") or vuln.get("url") or vuln.get("ip") or "?"
    name     = vuln.get("vuln_name") or vuln.get("name") or vuln.get("template") or vuln.get("title") or "?"
    details  = vuln.get("details") or vuln.get("description") or vuln.get("info") or ""
    fields = [
        {"name": "Programa",    "value": f"`{program_name}`",  "inline": True},
        {"name": "Severidade",  "value": sev.upper(),          "inline": True},
        {"name": "Vuln/Info",   "value": f"`{name}`",          "inline": False},
        {"name": "Host/URL",    "value": f"`{host}`",          "inline": False},
    ]
    if details:
        fields.append({"name": "Detalhes", "value": details[:1024], "inline": False})
    _discord_post({
        "embeds": [{
            "title":       f"🚨 {name}",
            "color":       color,
            "fields":      fields,
            "footer":      {"text": "AutoBB · scan4all"},
            "timestamp":   datetime.utcnow().isoformat() + "Z",
        }]
    })


def discord_notify_scan_done(program_name: str, domains: list, vulns: list, duration_s: int) -> None:
    """Manda resumo no Discord ao terminar o scan de um programa."""
    by_sev: dict = {}
    for v in vulns:
        s = v.get("severity", "info").lower()
        by_sev[s] = by_sev.get(s, 0) + 1

    sev_line = "  ".join(f"{s.upper()}: {c}" for s, c in sorted(by_sev.items())) if by_sev else "Nenhuma"
    mins, secs = divmod(duration_s, 60)
    color = 0xFF0000 if by_sev.get("critical") or by_sev.get("high") else (
            0xFFCC00 if by_sev.get("medium") else 0x00CC44)
    _discord_post({
        "embeds": [{
            "title":  f"✅ Scan concluído · {program_name}",
            "color":  color,
            "fields": [
                {"name": "Domínios escaneados", "value": str(len(domains)),    "inline": True},
                {"name": "Vulns encontradas",   "value": str(len(vulns)),      "inline": True},
                {"name": "Duração",             "value": f"{mins}m {secs}s",  "inline": True},
                {"name": "Por severidade",      "value": sev_line,            "inline": False},
            ],
            "footer":    {"text": "AutoBB · scan4all"},
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }]
    })


# ─── Estado global do worker ─────────────────────────────────────────────────

class WorkerState:
    """Singleton que mantém o estado atual do worker em memória."""

    def __init__(self) -> None:
        self.running: bool = False
        self.current_program: str = ""
        self.current_step: str = ""
        self.total_programs: int = 0
        self.done_programs: int = 0
        self.started_at: Optional[str] = None
        self.finished_at: Optional[str] = None
        self.last_error: str = ""
        # Programas sendo processados agora: {name: step}
        self.active_programs: Dict[str, str] = {}
        # Lock para acesso thread-safe ao estado
        self._lock: threading.Lock = threading.Lock()
        # Últimas 200 linhas de log ao vivo
        self.logs: deque = deque(maxlen=200)
        # Logs por programa: {program_name: [linhas]} — acumulados durante o scan
        self._prog_logs: Dict[str, List[str]] = {}
        # Filas SSE — uma por cliente conectado
        self._queues: List[asyncio.Queue] = []

    @property
    def progress(self) -> int:
        if self.total_programs == 0:
            return 0
        return int(self.done_programs * 100 / self.total_programs)

    def to_dict(self) -> dict:
        with self._lock:
            active = dict(self.active_programs)
        return {
            "running": self.running,
            "current_program": self.current_program,
            "current_step": self.current_step,
            "total_programs": self.total_programs,
            "done_programs": self.done_programs,
            "progress": self.progress,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "active_programs": active,
            "logs": list(self.logs),
        }

    def _push(self, event: dict) -> None:
        """Envia evento para todas as filas SSE ativas."""
        for q in list(self._queues):
            try:
                q.put_nowait(event)
            except Exception:
                pass

    def add_log(self, level: str, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        with self._lock:
            self.logs.append(line)
            # Detecta programa pelo prefixo [program_name]
            if msg.startswith("["):
                bracket_end = msg.find("]")
                if bracket_end > 1:
                    prog = msg[1:bracket_end].strip()
                    if prog and prog in self.active_programs:
                        if prog not in self._prog_logs:
                            self._prog_logs[prog] = []
                        self._prog_logs[prog].append(line)
        log.info(msg)
        self._push({"type": "log", "line": line})

    def get_prog_logs(self, program_name: str) -> List[str]:
        """Retorna logs acumulados de um programa específico."""
        with self._lock:
            return list(self._prog_logs.get(program_name, []))

    def set_active(self, program: str, step: str) -> None:
        """Registra/atualiza o step de um programa que está rodando agora."""
        with self._lock:
            self.active_programs[program] = step
            # current_program aponta para o mais recente (compatibilidade)
            self.current_program = program
            self.current_step = step
        self._push({
            "type": "progress",
            "running": self.running,
            "current_program": self.current_program,
            "current_step": self.current_step,
            "done_programs": self.done_programs,
            "total_programs": self.total_programs,
            "progress": self.progress,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "active_programs": dict(self.active_programs),
        })

    def finish_active(self, program: str) -> None:
        """Remove programa da lista de ativos ao concluir."""
        with self._lock:
            self.active_programs.pop(program, None)
            self.done_programs += 1
        self._push({
            "type": "progress",
            "running": self.running,
            "current_program": self.current_program,
            "current_step": self.current_step,
            "done_programs": self.done_programs,
            "total_programs": self.total_programs,
            "progress": self.progress,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "active_programs": dict(self.active_programs),
        })

    def set_step(self, step: str, program: str = "") -> None:
        """Compat: usado para steps globais (início/fim)."""
        self.current_step = step
        if program:
            self.current_program = program
        self._push({
            "type": "progress",
            "running": self.running,
            "current_program": self.current_program,
            "current_step": self.current_step,
            "done_programs": self.done_programs,
            "total_programs": self.total_programs,
            "progress": self.progress,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "last_error": self.last_error,
            "active_programs": dict(self.active_programs),
        })

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._queues.remove(q)
        except ValueError:
            pass


# Instância global — importada pelo main.py
worker_state = WorkerState()


# ─── Subfinder (wildcard expansion) ─────────────────────────────────────────

def expand_wildcards_with_subfinder(domains: list, program_name: str) -> list:
    """
    Para cada domínio wildcard (*.example.com), executa subfinder e
    substitui o wildcard pelos subdomínios descobertos.
    Domínios normais são mantidos como estão.
    Thread-safe: cada chamada usa seu próprio arquivo temporário.
    """
    final: list = []
    wildcards = [d for d in domains if d.startswith("*.")]
    normals   = [d for d in domains if not d.startswith("*.")]

    # Domínios normais entram direto
    final.extend(normals)

    if not wildcards:
        return final

    worker_state.add_log("INFO", f"[{program_name}] {len(wildcards)} wildcard(s) → expandindo com subfinder")

    for wc in wildcards:
        # *.example.com → example.com
        base = wc.lstrip("*.").strip()
        if not base:
            continue

        worker_state.set_active(program_name, f"subfinder: {base}")
        try:
            result = subprocess.run(
                [SUBFINDER_BIN, "-d", base, "-silent"],
                capture_output=True,
                text=True,
                timeout=SUBFINDER_TIMEOUT,
            )
            subs = [s.strip() for s in result.stdout.splitlines() if s.strip()]
            if subs:
                worker_state.add_log("INFO", f"[{program_name}] subfinder({base}): {len(subs)} subdomínios")
                final.extend(subs)
            else:
                # Fallback: usa o domínio base se subfinder não encontrou nada
                worker_state.add_log("WARN", f"[{program_name}] subfinder({base}): nenhum resultado, usando base")
                final.append(base)
        except subprocess.TimeoutExpired:
            worker_state.add_log("WARN", f"[{program_name}] subfinder({base}): timeout, usando base")
            final.append(base)
        except FileNotFoundError:
            worker_state.add_log("ERROR", f"[{program_name}] subfinder não encontrado — instale: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            final.append(base)

    # Remove duplicatas mantendo ordem
    seen = set()
    deduped = []
    for d in final:
        if d not in seen:
            seen.add(d)
            deduped.append(d)

    worker_state.add_log("INFO", f"[{program_name}] Total após expansão: {len(deduped)} domínios únicos")
    return deduped


# ─── Scan4all ────────────────────────────────────────────────────────────────

def run_scan4all(domains: list, program_name: str = "") -> str:
    """
    Escreve os domínios em arquivo temporário e executa o scan4all.
    Cada chamada roda em um diretório temporário próprio para isolar o
    .DbCache do Badger — evita panic quando múltiplos workers rodam em paralelo.
    O diretório de configuração do scan4all é linkado via symlink para que
    templates/POCs estejam disponíveis sem precisar copiar 28MB por processo.
    Retorna o output combinado (stdout + stderr).
    """
    prefix = f"[{program_name}] " if program_name else ""

    # Diretório do backend (onde fica config/)
    backend_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(backend_dir)

    # Workdir fixo por programa em /tmp (não /var/folders — no macOS tempfile.gettempdir()
    # retorna /var/folders/... e os dirs não são limpos entre runs pelo OS).
    # Dir sempre deletado e recriado do zero para garantir .DbCache virgem.
    workdir = f"/tmp/scan4all_{program_name}"
    if os.path.exists(workdir):
        shutil.rmtree(workdir, ignore_errors=True)
    os.makedirs(workdir, exist_ok=True)

    # Limpa também qualquer dir residual em /var/folders (runs anteriores)
    import glob as _glob
    _vf_base = tempfile.gettempdir()
    for _old in _glob.glob(os.path.join(_vf_base, f"scan4all_{program_name}*")):
        shutil.rmtree(_old, ignore_errors=True)

    # Symlink config/ → backend/config/ para que templates/POCs estejam disponíveis
    config_src = os.path.join(backend_dir, "config")
    config_dst = os.path.join(workdir, "config")
    if os.path.isdir(config_src):
        os.symlink(config_src, config_dst)

    # Usar o arquivo persistente em programs/<program_name>/domains.txt
    prog_dir = os.path.join(project_root, "programs", program_name)
    domains_file = os.path.join(prog_dir, "domains.txt")

    worker_state.add_log("INFO", f"{prefix}Arquivo: {domains_file} ({len(domains)} domínios)")

    # Apaga TODOS os .DbCache e resume.cfg que o scan4all possa encontrar subindo
    # a árvore de diretórios — sem limpeza ele pula hosts com
    # "Resume - Port scan already completed".
    _hacking_dir = os.path.dirname(os.path.dirname(project_root))  # HACKING/
    _autobb_dir  = os.path.dirname(project_root)                    # AUTOBB/
    _stale_paths = [
        os.path.join(backend_dir,   ".DbCache"),
        os.path.join(backend_dir,   "config", "scan4all_db"),
        os.path.join(backend_dir,   "resume.cfg"),
        os.path.join(project_root,  ".DbCache"),
        os.path.join(project_root,  "resume.cfg"),
        os.path.join(_autobb_dir,   ".DbCache"),
        os.path.join(_autobb_dir,   "resume.cfg"),
        os.path.join(_hacking_dir,  ".DbCache"),
        os.path.join(_hacking_dir,  "resume.cfg"),
    ]
    for _p in _stale_paths:
        try:
            if os.path.isdir(_p):
                shutil.rmtree(_p)
                worker_state.add_log("INFO", f"{prefix}Removido: {_p}")
            elif os.path.isfile(_p):
                os.remove(_p)
                worker_state.add_log("INFO", f"{prefix}Removido: {_p}")
        except Exception as e:
            worker_state.add_log("WARN", f"{prefix}Falha ao remover {_p}: {e}")

    hosts_arg = ",".join(domains)
    nmap_cli = (
        "nmap -n --unique --resolve-all -Pn "
        "--min-hostgroup 64 --max-retries 0 --host-timeout 10m "
        "--script-timeout 3m --version-intensity 9 "
        "--min-rate 10000 -T4"
    )
    cmd = [SCAN4ALL_BIN, "-host", hosts_arg, "-v", "-stream", "-nmap-cli", nmap_cli]
    worker_state.add_log("INFO", f"{prefix}Comando: {SCAN4ALL_BIN} -host <{len(domains)} hosts> -v -stream -nmap-cli '...'")

    _scan_start = datetime.utcnow()
    proc = None
    output = ""
    cancelled = Falseelled = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr no stdout
            text=True,
            cwd=workdir,
        )
        lines = []
        # Lê linha a linha para poder abortar se _SHUTDOWN for setado
        for line in proc.stdout:
            if _SHUTDOWN.is_set():
                cancelled = True
                worker_state.add_log("WARN", f"{prefix}Cancelado pelo usuário, abortando scan4all...")
                proc.kill()
                proc.wait(timeout=5)
                break
            lines.append(line)
            # Timeout manual
            elapsed = (datetime.utcnow() - _scan_start).total_seconds()
            if elapsed > SCAN_TIMEOUT:
                worker_state.add_log("WARN", f"{prefix}Scan expirou após {SCAN_TIMEOUT}s")
                proc.kill()
                proc.wait(timeout=5)
                lines.append(f"[TIMEOUT after {SCAN_TIMEOUT}s]\n")
                break
        output = "".join(lines)
        if not cancelled and proc.poll() is None:
            proc.wait(timeout=10)
    except FileNotFoundError:
        msg = f"{prefix}Binário '{SCAN4ALL_BIN}' não encontrado. Verifique SCAN4ALL_BIN no .env"
        worker_state.add_log("ERROR", msg)
        output = f"[ERROR] {msg}"
    except (KeyboardInterrupt, SystemExit):
        _SHUTDOWN.set()
        cancelled = True
        if proc and proc.poll() is None:
            proc.kill()
        raise
    finally:
        if proc and proc.poll() is None:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass

        # Remove resume.cfg e workdir
        _resume_paths = [
            os.path.join(workdir,       "resume.cfg"),
            os.path.join(backend_dir,   "resume.cfg"),
            os.path.join(project_root,  "resume.cfg"),
            os.path.join(_autobb_dir,   "resume.cfg"),
            os.path.join(_hacking_dir,  "resume.cfg"),
        ]
        for _rp in _resume_paths:
            try:
                if os.path.isfile(_rp):
                    os.remove(_rp)
                    worker_state.add_log("INFO", f"{prefix}resume.cfg removido: {_rp}")
            except Exception:
                pass
        shutil.rmtree(workdir, ignore_errors=True)

    # Sinaliza cancelamento no output para process_program detectar
    if cancelled or _SHUTDOWN.is_set():
        return "[CANCELLED]"
    return output


# ─── Process program ─────────────────────────────────────────────────────────

def process_program(program: dict) -> None:
    """
    Processa um programa: busca escopo, executa scan e salva resultados.
    Thread-safe — pode rodar em paralelo com outros process_program.
    """
    program_name = program.get("program_name", "").strip()
    scope_url    = program.get("latest_scope_version_id", "")

    if not program_name:
        worker_state.add_log("WARN", "Programa sem program_name, pulando.")
        return

    worker_state.set_active(program_name, "Buscando escopo...")
    worker_state.add_log("INFO", f"[+] [{program_name}] Iniciando processamento")

    _prog_start = datetime.utcnow()
    _final_domains: list = []
    _final_vulns: list = []

    try:
        # 1. Buscar escopo
        domains = get_program_scope(handle=program_name, scope_url=scope_url)

        if not domains:
            worker_state.add_log("WARN", f"[{program_name}] Nenhum domínio no escopo, pulando.")
            return

        preview = ", ".join(domains[:5]) + ("..." if len(domains) > 5 else "")
        worker_state.add_log("INFO", f"[{program_name}] Escopo bruto: {len(domains)} entradas: {preview}")

        # 1b. Expandir wildcards com subfinder
        worker_state.set_active(program_name, "Expandindo wildcards...")
        domains = expand_wildcards_with_subfinder(domains, program_name)

        if not domains:
            worker_state.add_log("WARN", f"[{program_name}] Nenhum domínio após expansão, pulando.")
            return

        preview2 = ", ".join(domains[:5]) + ("..." if len(domains) > 5 else "")
        worker_state.add_log("INFO", f"[{program_name}] {len(domains)} domínios finais: {preview2}")

        # Garantia: nunca passar wildcards residuais para o scan4all
        wildcards_restantes = [d for d in domains if d.startswith("*.")]
        if wildcards_restantes:
            worker_state.add_log("WARN", f"[{program_name}] Removendo {len(wildcards_restantes)} wildcard(s) não expandidos: {wildcards_restantes}")
            domains = [d for d in domains if not d.startswith("*.")]

        if not domains:
            worker_state.add_log("WARN", f"[{program_name}] Nenhum domínio válido após filtro de wildcards, pulando.")
            return

        # 1c. Salvar domínios em ./programs/<program_name>/domains.txt
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        prog_dir = os.path.join(project_root, "programs", program_name)
        os.makedirs(prog_dir, exist_ok=True)
        domains_file_persistent = os.path.join(prog_dir, "domains.txt")
        with open(domains_file_persistent, "w") as _df:
            _df.write("\n".join(domains) + "\n")
        worker_state.add_log("INFO", f"[{program_name}] Domínios salvos em: {domains_file_persistent}")
        _final_domains = domains

        # 2. Executar scan4all
        worker_state.set_active(program_name, f"scan4all ({len(domains)} domínios)")
        worker_state.add_log("INFO", f"[{program_name}] Iniciando scan4all...")
        raw_output = run_scan4all(domains, program_name)

        # 3. Salvar scan — logs = stdout/stderr real do scan4all
        if _SHUTDOWN.is_set() or raw_output == "[CANCELLED]":
            worker_state.add_log("WARN", f"[{program_name}] Cancelado, não salvando resultados.")
            return

        worker_state.set_active(program_name, "Salvando no Supabase...")
        scan4all_lines = [l for l in raw_output.splitlines() if l.strip()]
        scan = save_scan(
            program_name=program_name,
            domains=domains,
            raw_output=raw_output,
            status="completed",
            scan_logs=scan4all_lines,
        )
        scan_id = scan.get("id", "unknown")
        worker_state.add_log("INFO", f"[{program_name}] Scan salvo: ID={scan_id}")

        # 4. Parse e salvar vulns
        vulns = parse_scan4all_output(raw_output)
        _final_vulns = vulns
        worker_state.add_log("INFO", f"[{program_name}] {len(vulns)} vulnerabilidades encontradas")

        if vulns:
            save_vulnerabilities(scan_id=scan_id, program_name=program_name, vulns=vulns)
            by_sev: dict = {}
            for v in vulns:
                by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
            worker_state.add_log("INFO", f"[{program_name}] Severidades: {by_sev}")
            # Notifica cada vuln individualmente no Discord
            for v in vulns:
                discord_notify_vuln(program_name, v)

    except Exception:
        raise
    finally:
        # Só notifica resumo no Discord se não foi cancelado pelo usuário
        if not _SHUTDOWN.is_set():
            duration = int((datetime.utcnow() - _prog_start).total_seconds())
            discord_notify_scan_done(program_name, _final_domains, _final_vulns, duration)
        worker_state.finish_active(program_name)


# ─── Worker cycles ───────────────────────────────────────────────────────────

def run_worker_once() -> None:
    """Executa um ciclo completo do worker com scans em paralelo."""
    if worker_state.running:
        log.warning("Worker já está rodando, ignorando disparo duplicado.")
        return

    worker_state.running = True
    worker_state.started_at = datetime.now().isoformat()
    worker_state.finished_at = None
    worker_state.last_error = ""
    worker_state.done_programs = 0
    worker_state.active_programs = {}
    worker_state._prog_logs = {}
    worker_state.logs.clear()
    worker_state.set_step("Iniciando...")

    worker_state.add_log("INFO", "=" * 50)
    worker_state.add_log("INFO", f"Worker iniciado em {worker_state.started_at}")
    worker_state.add_log("INFO", f"Paralelismo: {PARALLEL_WORKERS} programas simultâneos")
    worker_state.add_log("INFO", "=" * 50)

    try:
        programs = get_all_programs()
        worker_state.total_programs = len(programs)
        worker_state.add_log("INFO", f"Programas encontrados: {len(programs)}")

        if not programs:
            worker_state.add_log("WARN", "Nenhum programa encontrado. Verifique a tabela no Supabase.")
        else:
            # Filtra programas já scaneados nas últimas RESCAN_HOURS horas
            recently_scanned = get_recently_scanned(within_hours=RESCAN_HOURS)
            pending = [p for p in programs if p.get("program_name") not in recently_scanned]
            skipped = len(programs) - len(pending)
            if skipped:
                worker_state.add_log("INFO", f"{skipped} programa(s) pulados (já scaneados nas últimas {RESCAN_HOURS}h)")
            programs = pending
            worker_state.total_programs = len(programs)

            if not programs:
                worker_state.add_log("INFO", "Todos os programas já foram scaneados recentemente. Nada a fazer.")
            else:
                worker_state.add_log(
                    "INFO",
                    f"Iniciando pool de {PARALLEL_WORKERS} workers para {len(programs)} programas..."
                )
                with ThreadPoolExecutor(max_workers=PARALLEL_WORKERS, thread_name_prefix="scan") as pool:
                    futures = {pool.submit(process_program, p): p for p in programs}
                    for future in as_completed(futures):
                        program = futures[future]
                        name = program.get("program_name", "?")
                        try:
                            future.result()  # propaga exceções
                            worker_state.add_log(
                                "INFO",
                                f"[✓] {name} concluído "
                                f"({worker_state.done_programs}/{worker_state.total_programs})"
                            )
                        except Exception as e:
                            worker_state.add_log("ERROR", f"[✗] Erro em '{name}': {e}")
                            worker_state.last_error = str(e)

    except KeyboardInterrupt:
        _SHUTDOWN.set()
        worker_state.add_log("WARN", "Worker interrompido pelo usuário (Ctrl+C).")
    except Exception as e:
        worker_state.add_log("ERROR", f"Erro fatal no worker: {e}")
        worker_state.last_error = str(e)
    finally:
        worker_state.running = False
        worker_state.finished_at = datetime.now().isoformat()
        worker_state.active_programs = {}
        worker_state.current_step = "Finalizado"
        worker_state.current_program = ""
        worker_state.set_step("Finalizado")
        if not _SHUTDOWN.is_set():
            worker_state.add_log("INFO", "=" * 50)
            worker_state.add_log(
                "INFO",
                f"Ciclo completo: {worker_state.done_programs} programas em "
                f"{(datetime.fromisoformat(worker_state.finished_at) - datetime.fromisoformat(worker_state.started_at)).seconds // 60}min"
            )
            worker_state.add_log("INFO", "=" * 50)


def run_forever() -> None:
    """Loop infinito do worker."""
    log.info(f"Worker rodando a cada {WORKER_INTERVAL}s ({WORKER_INTERVAL // 3600}h)")
    while not _SHUTDOWN.is_set():
        run_worker_once()
        if _SHUTDOWN.is_set():
            break
        log.info(f"Próximo ciclo em {WORKER_INTERVAL}s. Aguardando...")
        try:
            _SHUTDOWN.wait(timeout=WORKER_INTERVAL)
        except KeyboardInterrupt:
            break
    log.info("Worker encerrado.")


if __name__ == "__main__":
    run_forever()
