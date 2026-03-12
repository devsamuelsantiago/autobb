"""
AutoBB - Backend API
FastAPI server que expõe endpoints para o frontend consumir resultados de scans.
"""

import asyncio
import json
import os

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

from db import get_all_scans, get_scan_by_id, get_vuln_stats, get_programs_stats, get_all_programs, get_program_scans, get_program_vulns, get_last_scan_per_program
from worker import run_worker_once, worker_state

app = FastAPI(title="AutoBB API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend estático
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path, html=True), name="static")


@app.get("/")
def root():
    index_path = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "AutoBB API running. Access /docs for Swagger UI."}


@app.get("/api/stats/vulns")
def vuln_stats():
    """Retorna contagem de vulnerabilidades por severidade."""
    try:
        return get_vuln_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/stats/programs")
def programs_stats():
    """Retorna vulnerabilidades agrupadas por programa."""
    try:
        return get_programs_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans")
def list_scans(limit: int = 50, offset: int = 0):
    """Lista todos os scans com paginação."""
    try:
        return get_all_scans(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    """Retorna detalhes de um scan específico."""
    try:
        scan = get_scan_by_id(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan não encontrado")
        return scan
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/programs")
def list_programs():
    """Lista todos os programas cadastrados, enriquecidos com last_scanned."""
    try:
        programs = get_all_programs()
        last_scan = get_last_scan_per_program()
        for p in programs:
            name = p.get("program_name", "")
            p["last_scanned"] = last_scan.get(name)
        # Não scaneados primeiro; entre os scaneados, mais antigo primeiro
        programs.sort(key=lambda p: (p["last_scanned"] is not None, p["last_scanned"] or ""))
        return programs
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/programs/{program_name:path}")
def program_detail(program_name: str):
    """Retorna detalhes de um programa: info básica, scans e vulnerabilidades."""
    try:
        programs = get_all_programs()
        prog = next((p for p in programs if p.get("program_name") == program_name), None)
        scans = get_program_scans(program_name)
        vulns = get_program_vulns(program_name)
        sev_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for v in vulns:
            sev = v.get("severity", "info")
            if sev in sev_counts:
                sev_counts[sev] += 1
        return {
            "program": prog,
            "scans": scans,
            "vulns": vulns,
            "stats": sev_counts,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/run-worker")
async def trigger_worker(background_tasks: BackgroundTasks):
    """Dispara o worker manualmente em background."""
    if worker_state.running:
        return {"message": "Worker já está rodando", "already_running": True}
    background_tasks.add_task(run_worker_once)
    return {"message": "Worker disparado em background", "already_running": False}


@app.get("/api/worker/status")
def worker_status():
    """Retorna o estado atual do worker (snapshot JSON)."""
    return worker_state.to_dict()


@app.get("/api/worker/stream")
async def worker_stream(request: Request):
    """
    Server-Sent Events — push em tempo real do progresso do worker.
    O cliente conecta uma vez e recebe eventos enquanto o worker roda.
    """
    queue = worker_state.subscribe()

    async def event_generator():
        # Envia snapshot inicial
        snapshot = worker_state.to_dict()
        snapshot.pop("logs", None)  # logs completos vêm por evento individual
        yield f"data: {json.dumps({'type': 'snapshot', **snapshot})}\n\n"

        # Manda os logs históricos de uma vez
        for line in list(worker_state.logs):
            yield f"data: {json.dumps({'type': 'log', 'line': line})}\n\n"

        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=25.0)
                    yield f"data: {json.dumps(event)}\n\n"
                except asyncio.TimeoutError:
                    # heartbeat para manter a conexão viva
                    yield ": heartbeat\n\n"
        finally:
            worker_state.unsubscribe(queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
