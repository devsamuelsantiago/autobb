#!/bin/bash
# Setup AutoBB na Oracle Cloud Free Tier (Ubuntu 22.04 ARM)
set -e

echo "==> Atualizando sistema..."
apt update && apt upgrade -y

echo "==> Instalando dependências..."
apt install -y python3 python3-pip python3-venv git curl wget unzip

echo "==> Instalando Go..."
wget -q https://go.dev/dl/go1.22.0.linux-arm64.tar.gz
tar -C /usr/local -xzf go1.22.0.linux-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin:/root/go/bin' >> /root/.bashrc
export PATH=$PATH:/usr/local/go/bin:/root/go/bin

echo "==> Instalando subfinder..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "==> Instalando scan4all..."
go install github.com/GangGreenTemperTatum/scan4all@latest

echo "==> Clonando autobb..."
# Substitua pela URL do seu repositório
git clone https://github.com/SEU_USUARIO/autobb.git /root/autobb
cd /root/autobb

echo "==> Criando virtualenv..."
python3 -m venv venv
venv/bin/pip install -r backend/requirements.txt

echo "==> Configurando .env..."
cat > /root/autobb/.env << 'EOF'
# Cole aqui o conteúdo do seu .env
SUPABASE_URL=
SUPABASE_KEY=
H1_CSRF_TOKEN=
SCAN4ALL_BIN=/root/go/bin/scan4all
SUBFINDER_BIN=/root/go/bin/subfinder
SUBFINDER_TIMEOUT=1200000
SCAN_TIMEOUT=36000
WORKER_INTERVAL=21600
PARALLEL_WORKERS=3
RESCAN_HOURS=48
DISCORD_WEBHOOK=
EOF

echo "==> Instalando serviço systemd..."
cat > /etc/systemd/system/autobb.service << 'EOF'
[Unit]
Description=AutoBB Bug Bounty Worker
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/autobb/backend
ExecStart=/root/autobb/venv/bin/python -m uvicorn main:app --host 0.0.0.0 --port 8000 --log-level warning
Restart=always
RestartSec=15
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable autobb
systemctl start autobb

echo ""
echo "==> Pronto! Status do serviço:"
systemctl status autobb --no-pager

echo ""
echo "==> Abra a porta 8000 no firewall da Oracle:"
echo "    Console Oracle → Networking → VCN → Security Lists → Add Ingress Rule"
echo "    Source CIDR: 0.0.0.0/0 | Destination Port: 8000"
echo "    (ou use: iptables -I INPUT -p tcp --dport 8000 -j ACCEPT)"
