# AutoBB 🎯

Automação de Bug Bounty com Python + Supabase + HackerOne GraphQL + scan4all.

## Arquitetura

```
autobb/
├── backend/
│   ├── main.py        → API FastAPI (serve frontend + endpoints REST)
│   ├── worker.py      → Loop de automação (Supabase → H1 GraphQL → scan4all → Supabase)
│   ├── db.py          → Camada de dados Supabase
│   ├── hackerone.py   → Cliente GraphQL HackerOne
│   └── parser.py      → Parser do output JSON do scan4all
├── frontend/
│   └── index.html     → Dashboard web (Chart.js, dark theme)
├── supabase_schema.sql → SQL para criar as tabelas
├── .env.example        → Template de variáveis de ambiente
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── start.sh            → Script de start local
```

## Fluxo

```
Supabase (programs) 
    ↓
HackerOne GraphQL → scope (domínios)
    ↓
scan4all -l domains.txt -v -json
    ↓
Parser (severidade, host, vuln_name)
    ↓
Supabase (scans + vulnerabilities)
    ↓
FastAPI /api/stats/*
    ↓
Dashboard (gráficos donut + bar + stacked + tabela)
```

## Setup

### 1. Banco de dados (Supabase)

1. Acesse [app.supabase.com](https://app.supabase.com) e crie um projeto
2. Vá em **SQL Editor** e execute o conteúdo de `supabase_schema.sql`
3. Adicione seus programas na tabela `programs`:
   ```sql
   insert into programs (handle, name) values ('shopify', 'Shopify');
   ```

### 2. Credenciais HackerOne

Gere seu token em: https://hackerone.com/settings/api_token/edit

### 3. Configuração

```bash
cd autobb
cp .env.example .env
# edite o .env com suas credenciais
```

### 4. Rodar localmente

```bash
# Criar venv e instalar dependências
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Subir tudo
bash start.sh
```

Acesse: http://localhost:8000

### 5. Rodar com Docker

```bash
docker-compose up --build
```

## Variáveis de ambiente

| Variável | Descrição |
|---|---|
| `SUPABASE_URL` | URL do projeto Supabase |
| `SUPABASE_KEY` | Chave anon/service do Supabase |
| `H1_USERNAME` | Usuário HackerOne |
| `H1_API_TOKEN` | Token da API HackerOne |
| `SCAN4ALL_BIN` | Caminho do binário scan4all (default: `scan4all`) |
| `SCAN_TIMEOUT` | Timeout por programa em segundos (default: 7200) |
| `WORKER_INTERVAL` | Intervalo entre ciclos em segundos (default: 21600 = 6h) |

## API Endpoints

| Método | Rota | Descrição |
|---|---|---|
| GET | `/api/stats/vulns` | Contagem por severidade |
| GET | `/api/stats/programs` | Findings por programa |
| GET | `/api/programs` | Lista de programas |
| GET | `/api/scans` | Histórico de scans |
| GET | `/api/scans/{id}` | Detalhes de um scan |
| POST | `/api/run-worker` | Dispara scan manual |
| GET | `/docs` | Swagger UI |

## scan4all

Certifique-se que o binário `scan4all` está no PATH ou defina `SCAN4ALL_BIN` no `.env`.

O worker executa: `scan4all -l <arquivo_de_dominios> -v -json`

O parser suporta tanto o output JSON por linha (nuclei/scan4all com `-json`) quanto o formato texto padrão `[severity] [template-id] target`.
