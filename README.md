# 🛡️ SOC/NOC Platform - Security Operations & Network Operations Center

> **⚠️ AVISO ÉTICO:** Esta plataforma foi desenvolvida **exclusivamente para ambientes autorizados e laboratoriais**, com foco educacional e demonstração prática de habilidades em Blue Team, Threat Hunting e Resposta a Incidentes. O uso em ambientes de produção sem autorização é estritamente proibido.

## 📋 Visão Geral

Plataforma completa de monitoramento de segurança (SOC) e operações de rede (NOC) modular, escalável e próxima de um ambiente real de SOC.

### Funcionalidades Principais

- ✅ Monitoramento de eventos de rede e sistema em tempo real
- ✅ Detecção de atividades suspeitas (brute force SSH, scans, anomalias)
- ✅ Honeypot SSH integrado para coleta de ameaças
- ✅ Alertas inteligentes e priorizados
- ✅ Análise forense básica
- ✅ Dashboards profissionais em tempo real
- ✅ Threat Hunting com queries customizadas
- ✅ Relatórios automatizados (HTML, PDF, Markdown)
- ✅ Integração com MITRE ATT&CK
- ✅ Playbooks automatizados de resposta a incidentes
- ✅ Deploy com Docker Compose

## 🏗️ Arquitetura

```
┌─────────────────────────────────────────────────────────────┐
│                     SOC/NOC Platform                        │
├─────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Honeypot │  │  Agents  │  │  Wazuh   │  │ tcpdump  │   │
│  │   SSH    │  │ (Python) │  │  (HIDS)  │  │  (PCAP)  │   │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘   │
│       │              │              │              │         │
│       └──────────────┴──────┬───────┴──────────────┘         │
│                             ▼                                │
│                    ┌─────────────────┐                        │
│                    │  Redis Streams  │ ◄── Fila de Mensagens │
│                    └────────┬────────┘                        │
│                             ▼                                │
│                    ┌─────────────────┐                        │
│                    │   Processor     │ ◄── Parsing/Enrichment│
│                    │   (Python)      │                        │
│                    └────────┬────────┘                        │
│                             ▼                                │
│       ┌─────────────────────┴─────────────────────┐          │
│       ▼                                           ▼          │
│  ┌──────────────┐                          ┌──────────┐      │
│  │Elasticsearch │ ◄── Logs & Events        │PostgreSQL│      │
│  │  / OpenSearch│                          │  (Meta)  │      │
│  └──────────────┘                          └──────────┘      │
│                             ▼                                │
│                    ┌─────────────────┐                        │
│                    │   Backend API   │                        │
│                    │   (FastAPI)     │                        │
│                    └────────┬────────┘                        │
│                             ▼                                │
│       ┌─────────────────────┴─────────────────────┐          │
│       ▼                                           ▼          │
│  ┌──────────────┐                          ┌──────────┐      │
│  │   Dashboard  │                          │ Reports  │      │
│  │   (React)    │                          │ Engine   │      │
│  └──────────────┘                          └──────────┘      │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Início Rápido

### Pré-requisitos

- Docker >= 20.10
- Docker Compose >= 2.0
- Python >= 3.11 (para desenvolvimento local)
- Node.js >= 18 (para desenvolvimento local)

### Deploy com Docker Compose

```bash
# Clonar o repositório
git clone <repo-url>
cd soc-noc-platform

# Subir todos os serviços
docker compose up -d

# Verificar status
docker compose ps

# Acessar dashboard
# http://localhost:3000
# Login: admin / admin123
```

### Desenvolvimento Local

```bash
# Backend
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev

# Honeypot
cd honeypot
pip install -r requirements.txt
python main.py

# Agents
cd agents
pip install -r requirements.txt
python collector.py
```

## 📁 Estrutura do Projeto

```
soc-noc-platform/
├── backend/                 # API REST (FastAPI)
│   ├── app/
│   │   ├── main.py         # Entry point
│   │   ├── api/            # Rotas da API
│   │   ├── core/           # Config e segurança
│   │   ├── models/         # Modelos de dados
│   │   ├── services/       # Lógica de negócio
│   │   └── detectors/      # Motor de detecção
│   └── requirements.txt
├── frontend/               # Dashboard (React)
│   ├── src/
│   │   ├── components/     # Componentes React
│   │   ├── pages/          # Páginas
│   │   ├── services/       # API client
│   │   └── utils/          # Utilitários
│   └── package.json
├── honeypot/               # Honeypot SSH
│   ├── main.py
│   └── requirements.txt
├── agents/                 # Coletores de logs
│   ├── collector.py
│   └── requirements.txt
├── processor/              # Pipeline de dados
│   ├── main.py
│   └── requirements.txt
├── reports/                # Engine de relatórios
│   ├── generator.py
│   └── templates/
├── docker/                 # Configurações Docker
│   ├── docker-compose.yml
│   └── Dockerfiles/
├── docs/                   # Documentação educacional
│   └── SOC_EDUCATIONAL.md
├── playbooks/              # Playbooks automatizados
│   └── playbooks.yaml
└── mitre_attack/           # Integração MITRE ATT&CK
    └── mapping.py
```

## 🎯 Funcionalidades Detalheadas

### Monitoramento
- Logs de autenticação (SSH, sudo)
- Conexões de rede ativas
- Processos suspeitos em execução

### Detecção e Alertas
- Brute force SSH
- Port scanning
- Execução de comandos suspeitos
- Níveis: baixo, médio, crítico
- Notificações: console, e-mail, webhook, Slack/Discord

### Honeypot SSH
- Simulação de servidor SSH
- Captura de credenciais tentadas
- Registro de comandos executados
- Identificação e geolocalização de IPs

### Análise Forense
- Consulta histórica de eventos
- Filtros por IP, tempo, tipo de ataque
- Visualização de sessões maliciosas

### Threat Hunting
- Interface para queries customizadas
- Busca por padrões (IPs recorrentes, tentativas distribuídas)
- Correlação de eventos

### Dashboard
- KPIs: tentativas de login, IPs únicos, tipos de ataque
- Gráficos: timeline, distribuição geográfica, top eventos
- Mapa de ataques em tempo real

### Relatórios
- Resumo executivo
- Principais incidentes detectados
- IOCs (Indicadores de Comprometimento)
- Análise de ataques ao honeypot
- Tendências observadas
- Recomendações de segurança

## 🔧 Tecnologias

| Camada | Tecnologia |
|--------|-----------|
| Honeypot | Python + Paramiko |
| Agents | Python + asyncio |
| Message Queue | Redis Streams |
| Processing | Python + asyncio |
| Log Storage | Elasticsearch |
| Relational DB | PostgreSQL |
| Backend API | Python + FastAPI |
| Frontend | React + TypeScript + Vite |
| Charts | Recharts + Leaflet |
| Containers | Docker + Docker Compose |

## 🔐 Controle de Acesso

Credenciais padrão (alterar em produção):
- **Usuário:** `admin`
- **Senha:** `admin123`

## 📚 Documentação Educacional

Para aprender sobre SOC, SIEM, SOAR, NOC e técnicas de detecção, consulte [docs/SOC_EDUCATIONAL.md](./docs/SOC_EDUCATIONAL.md).

## ⚖️ Licença

Este projeto é destinado **exclusivamente para fins educacionais e laboratoriais**.

---

> 🎓 **Nota:** Esta plataforma foi projetada para ambientes controlados. Sempre obtenha autorização antes de realizar qualquer tipo de monitoramento.
# Simulador-SOC
