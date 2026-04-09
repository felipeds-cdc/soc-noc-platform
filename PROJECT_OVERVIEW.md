# 🛡️ SOC/NOC Platform - Visão Geral do Projeto

## 📊 Resumo

A **SOC/NOC Platform** é uma solução completa de monitoramento de segurança e operações de rede, projetada exclusivamente para **ambientes laboratoriais e educacionais**.

### O que foi implementado

Este projeto inclui uma plataforma **completa e funcional** com:

| Componente | Tecnologia | Status |
|------------|-----------|--------|
| **Honeypot SSH** | Python + asyncssh | ✅ Completo |
| **Agentes de Coleta** | Python + asyncio | ✅ Completo |
| **Pipeline de Eventos** | Redis Streams | ✅ Completo |
| **Processador** | Python + Elasticsearch | ✅ Completo |
| **Backend API** | FastAPI + PostgreSQL | ✅ Completo |
| **Motor de Detecção** | Python (regras customizáveis) | ✅ Completo |
| **Threat Hunting** | API + Interface | ✅ Completo |
| **Relatórios** | Markdown, HTML, PDF | ✅ Completo |
| **Dashboard** | React + TypeScript + Recharts | ✅ Completo |
| **MITRE ATT&CK** | Mapeamento automático | ✅ Completo |
| **Playbooks** | Automação de resposta | ✅ Completo |
| **Simulador** | Geração de ataques de teste | ✅ Completo |
| **Docker** | Deploy completo | ✅ Completo |

## 🏗️ Arquitetura Implementada

```
┌─────────────────────────────────────────────────────────────────┐
│                    SOC/NOC Platform                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  COLETA DE DADOS:                                               │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Honeypot │  │  Agents  │  │  Wazuh   │  │ tcpdump  │       │
│  │   SSH    │  │ (Python) │  │  (HIDS)  │  │  (PCAP)  │       │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘       │
│       │              │              │              │             │
│       └──────────────┴──────┬───────┴──────────────┘             │
│                             ▼                                    │
│                    ┌─────────────────┐                           │
│                    │  Redis Streams  │ ◄── Mensageria           │
│                    └────────┬────────┘                           │
│                             ▼                                    │
│                    ┌─────────────────┐                           │
│                    │   Processor     │ ◄── Parsing/Enrichment   │
│                    │   (Python)      │    + GeoIP + Reputation  │
│                    └────────┬────────┘                           │
│                             ▼                                    │
│       ┌─────────────────────┴─────────────────────┐              │
│       ▼                                           ▼              │
│  ┌──────────────┐                          ┌──────────┐          │
│  │Elasticsearch │ ◄── Logs & Events        │PostgreSQL│          │
│  │  / OpenSearch│    (Full-text search)    │ (Meta)   │          │
│  └──────────────┘                          └──────────┘          │
│                             ▼                                    │
│                    ┌─────────────────┐                           │
│                    │   Backend API   │                           │
│                    │   (FastAPI)     │                           │
│                    │                 │                           │
│                    │  • Auth (JWT)   │                           │
│                    │  • Events CRUD  │                           │
│                    │  • Alerts       │                           │
│                    │  • Dashboard    │                           │
│                    │  • Hunt API     │                           │
│                    │  • Reports      │                           │
│                    └────────┬────────┘                           │
│                             ▼                                    │
│       ┌─────────────────────┴─────────────────────┐              │
│       ▼                                           ▼              │
│  ┌──────────────┐                          ┌──────────┐          │
│  │   Dashboard  │                          │ Reports  │          │
│  │   (React)    │                          │ Engine   │          │
│  │              │                          │          │          │
│  │ • KPIs       │                          │ • HTML   │          │
│  │ • Charts     │                          │ • PDF    │          │
│  │ • Timeline   │                          │ • MD     │          │
│  │ • Maps       │                          │          │          │
│  └──────────────┘                          └──────────┘          │
│                                                                 │
│  EXTRAS:                                                        │
│  ┌──────────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ MITRE ATT&CK │  │Playbooks │  │ Anomaly  │  │Simulator │   │
│  │  Mapping     │  │  Engine  │  │ Detect   │  │  (Lab)   │   │
│  └──────────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## 📁 Estrutura de Arquivos

```
soc-noc-platform/
│
├── 📄 README.md                    # Documentação principal
├── 📄 QUICKSTART.md                # Guia de início rápido
├── 📄 CONTRIBUTING.md              # Guia de contribuição
├── 📄 LICENSE                      # Licença educacional
├── 📄 docker-compose.yml           # Orquestração de containers
├── 📄 .env.example                 # Variáveis de ambiente
├── 📄 .gitignore                   # Arquivos ignorados
├── 📄 start.sh                     # Script de inicialização
│
├── 📂 backend/                     # API REST (FastAPI)
│   ├── app/
│   │   ├── main.py                 # Entry point
│   │   ├── config.py               # Configurações
│   │   ├── models.py               # Modelos Pydantic
│   │   ├── security.py             # Auth JWT
│   │   ├── database.py             # Conexões DB
│   │   ├── services.py             # Lógica de negócio
│   │   ├── detector.py             # Motor de detecção
│   │   └── api/                    # Endpoints
│   │       ├── auth.py             # Autenticação
│   │       ├── events.py           # Eventos
│   │       ├── alerts.py           # Alertas
│   │       ├── dashboard.py        # Dashboard KPIs
│   │       ├── threat_hunting.py   # Threat Hunting
│   │       └── reports.py          # Relatórios
│   └── requirements.txt
│
├── 📂 frontend/                    # Dashboard (React + TS)
│   ├── src/
│   │   ├── App.tsx                 # Componente principal
│   │   ├── main.tsx                # Entry point
│   │   ├── index.css               # Estilos globais
│   │   ├── components/
│   │   │   └── Layout.tsx          # Layout com sidebar
│   │   ├── contexts/
│   │   │   └── AuthContext.tsx     # Contexto de auth
│   │   ├── services/
│   │   │   └── api.ts              # Cliente API
│   │   └── pages/
│   │       ├── Login.tsx           # Página de login
│   │       ├── Dashboard.tsx       # Dashboard principal
│   │       ├── Events.tsx          # Lista de eventos
│   │       ├── Alerts.tsx          # Lista de alertas
│   │       ├── Honeypot.tsx        # Dados do honeypot
│   │       ├── ThreatHunting.tsx   # Interface de hunting
│   │       └── Reports.tsx         # Geração de relatórios
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── nginx.conf
│   └── index.html
│
├── 📂 honeypot/                    # Honeypot SSH
│   ├── main.py                     # Servidor honeypot
│   └── requirements.txt
│
├── 📂 agents/                      # Coletores de logs
│   ├── collector.py                # Agente de coleta
│   └── requirements.txt
│
├── 📂 processor/                   # Pipeline de eventos
│   ├── main.py                     # Processador
│   └── requirements.txt
│
├── 📂 simulator/                   # Simulador de ataques
│   ├── main.py                     # Simulador
│   └── requirements.txt
│
├── 📂 playbooks/                   # Automação de resposta
│   ├── executor.py                 # Executor de playbooks
│   └── __init__.py
│
├── 📂 mitre_attack/                # Integração MITRE
│   ├── mapping.py                  # Mapeamento ATT&CK
│   └── __init__.py
│
├── 📂 docker/                      # Configurações Docker
│   ├── Dockerfile.backend
│   ├── Dockerfile.frontend
│   ├── Dockerfile.honeypot
│   ├── Dockerfile.agent
│   ├── Dockerfile.processor
│   ├── Dockerfile.simulator
│   └── init-db.sql                 # Inicialização PostgreSQL
│
└── 📂 docs/                        # Documentação
    └── SOC_EDUCATIONAL.md          # Guia educacional completo
```

## 🎯 Funcionalidades Implementadas

### ✅ Monitoramento em Tempo Real
- Coleta de logs de autenticação (SSH, sudo)
- Monitoramento de processos suspeitos
- Detecção de conexões anômalas
- Pipeline de eventos em tempo real

### ✅ Honeypot SSH
- Simulação de servidor SSH realista
- Captura de credenciais tentadas
- Registro de comandos executados
- Geolocalização de IPs
- Sessões completamente monitoradas

### ✅ Detecção Inteligente
- Brute force SSH (5+ tentativas)
- Port scanning (20+ portas)
- Execução de comandos suspeitos
- Possíveis reverse shells
- Ataques distribuídos
- Regras customizáveis

### ✅ Alertas e Notificações
- Severidade: baixo, médio, alto, crítico
- Status: triggered, acknowledged, resolved
- Múltiplos canais: console, email, Slack, Discord
- Playbooks automatizados de resposta

### ✅ Dashboard Profissional
- KPIs em tempo real
- Gráficos de linha do tempo
- Gráficos de barra e pizza
- Top IPs, eventos, países
- Sessões honeypot recentes
- Atualização automática (30s)

### ✅ Threat Hunting
- Busca customizada (Elasticsearch queries)
- Análise detalhada de IPs
- Correlação de eventos
- Identificação de padrões
- Timeline de ataques

### ✅ Relatórios Automatizados
- Resumo executivo
- Incidentes detalhados
- Análise de honeypot
- IOCs detectados
- Recomendações de segurança
- Formatos: Markdown, HTML, PDF

### ✅ MITRE ATT&CK
- Mapeamento automático de técnicas
- 10+ técnicas catalogadas
- Kill chain analysis
- Matriz ATT&CK visual

### ✅ Playbooks de Resposta
- Bloqueio automático de IPs
- Criação de tickets
- Notificações multi-canal
- Coleta de evidências
- Enriquecimento de IOCs
- 4 playbooks pré-configurados

### ✅ Simulador de Ataques
- Brute force automatizado
- Interação com honeypot
- Ataques distribuídos
- Geração de dados de teste
- Modo contínuo

### ✅ Segurança e Acesso
- Autenticação JWT
- Controle de acesso por role
- Multi-tenant (simulado)
- Logs anonimazáveis
- Aviso de uso ético

### ✅ Deploy e Infraestrutura
- Docker + Docker Compose
- 7 serviços orquestrados
- Health checks
- Volumes persistentes
- Script de inicialização
- Ambiente isolado

## 📚 Documentação Educacional

O projeto inclui documentação completa sobre:

✅ Como funciona um SOC  
✅ Diferença entre SIEM, SOAR e NOC  
✅ Técnicas de detecção (assinatura, anomalia, comportamento)  
✅ MITRE ATT&CK Framework  
✅ Métricas e KPIs de SOC  
✅ Threat Hunting methodologies  
✅ Incident Response (NIST)  
✅ Glossário completo  
✅ Referências para estudo  

## 🚀 Como Usar

### Início Rápido

```bash
# 1. Clone o repositório
git clone <url>
cd QWENcode

# 2. Inicie a plataforma
./start.sh start

# 3. Acesse o dashboard
# http://localhost:3000
# Login: admin / admin123

# 4. (Opcional) Inicie simulador
./start.sh simulator
```

### Ver Status

```bash
./start.sh status
```

### Ver Logs

```bash
./start.sh logs honeypot
./start.sh logs backend
```

### Parar

```bash
./start.sh stop
```

## 🎓 Uso Educacional

Este projeto foi projetado para:

- ✅ **Estudantes** de segurança cibernética
- ✅ **Profissionais** buscando prática em Blue Team
- ✅ **Recrutadores** avaliando habilidades técnicas
- ✅ **Instrutores** demonstrando conceitos de SOC
- ✅ **Pesquisadores** testando detecções

## 📈 Próximos Passos (Roadmap)

### Versão 1.1
- [ ] Testes unitários e de integração
- [ ] Integração com Wazuh
- [ ] Detecção de anomalias com ML
- [ ] Melhorias no dashboard
- [ ] Tema claro/escuro

### Versão 2.0
- [ ] Machine Learning avançado
- [ ] Plugin system
- [ ] API GraphQL
- [ ] Mobile responsive
- [ ] Multi-tenant real

## ⚠️ Avisos Importantes

1. **Uso Autorizado:** Esta plataforma deve ser usada **APENAS** em ambientes autorizados
2. **Laboratorial:** Destinada exclusivamente para fins educacionais e de demonstração
3. **Legal:** Sempre obtenha autorização antes de monitorar qualquer sistema
4. **Ético:** Não use para atividades maliciosas ou não autorizadas

## 📞 Suporte

- 📖 **Documentação:** Veja `README.md` e `docs/SOC_EDUCATIONAL.md`
- 🚀 **Quick Start:** Veja `QUICKSTART.md`
- 🤝 **Contribuir:** Veja `CONTRIBUTING.md`
- 🐛 **Issues:** Abra uma issue no repositório

## 📄 Licença

Educational Use License - Veja `LICENSE` para detalhes.

---

> **🛡️ SOC/NOC Platform**  
> *Plataforma completa de monitoramento de segurança para ambientes laboratoriais*  
> *Desenvolvida para fins educacionais e de demonstração técnica*

**Divirta-se aprendendo! 🎓**
