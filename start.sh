#!/usr/bin/env bash
# start.sh — Atalho para subir API e Worker localmente (sem Docker)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ ! -f .env ]]; then
  echo "[ERROR] Arquivo .env não encontrado. Copie .env.example e preencha."
  exit 1
fi

# Ativar venv se existir
if [[ -d .venv ]]; then
  source .venv/bin/activate
fi

# Instalar dependências se necessário
pip install -q -r requirements.txt

echo "[AutoBB] Subindo API em background (porta 8000)..."
python backend/main.py &
API_PID=$!

echo ""
echo "  API:    http://localhost:8000"
echo "  Docs:   http://localhost:8000/docs"
echo "  Dashboard: http://localhost:8000"
echo ""
echo "  PID: API=$API_PID"
echo "  Worker: inicie manualmente pelo botão no dashboard."
echo "  Pressione Ctrl+C para parar."

trap "kill $API_PID 2>/dev/null; echo ''; echo '[AutoBB] Encerrado.'" INT TERM

wait
