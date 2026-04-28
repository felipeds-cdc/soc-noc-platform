# 🚀 Guia de Início Rápido - SOC/NOC Platform

## Pré-requisitos

Antes de começar, certifique-se de ter:

- ✅ **Docker** >= 20.10 instalado
- ✅ **Docker Compose** >= 2.0 instalado
- ✅ Pelo menos **4GB RAM** disponível
- ✅ Pelo menos **10GB de espaço** em disco

## Instalação Rápida (5 minutos)

### 1. Clone o Repositório

```bash
git clone <url-do-repositorio>
cd soc-noc-platform
```

### 2. Configure as Variáveis de Ambiente

```bash
cp .env.example .env
# Edite .env se necessário (opcional para testes locais)
```

### 3. Inicie a Plataforma

```bash
# Usando o script de inicialização
./start.sh start

# OU manualmente
docker compose up -d
```

### 4. Verifique o Status

```bash
./start.sh status

# OU
docker compose ps
```

### 5. Acesse o Dashboard

Abra seu navegador e acesse:

- 🌐 **Dashboard:** http://localhost:3000
- 🔌 **API Docs:** http://localhost:8000/docs

**Credenciais padrão:**
- Usuário: `admin`
- Senha: `admin123`

## Testando a Plataforma

### Simular Ataques (Opcional)

Para gerar dados de teste e ver a plataforma em ação:

```bash
# Inicia simulador de ataques
./start.sh simulator

# Ou manualmente
docker compose --profile simulation up -d simulator
```

O simulador irá:
- Realizar tentativas de brute force SSH contra o honeypot
- Executar comandos simulados
- Gerar eventos para popular o dashboard

### Verificar Logs

```bash
# Logs de todos os serviços
./start.sh logs

# Logs de serviço específico
./start.sh logs backend
./start.sh logs honeypot
```

## Estrutura dos Serviços

| Serviço | Porta | Descrição |
|---------|-------|-----------|
| Frontend (Dashboard) | 3000 | Interface web React |
| Backend API | 8000 | API REST FastAPI |
| Honeypot SSH | 2222 | Honeypot para capturar ataques |
| Redis | 6379 | Fila de mensagens |
| Elasticsearch | 9200 | Armazenamento de logs |
| PostgreSQL | 5432 | Banco de dados relacional |

## Comandos Úteis

### Parar a Plataforma

```bash
./start.sh stop

# OU
docker compose downdocker compose --profile simulation up -d simulator
```

### Reiniciar

```bash
./start.sh restart
```

### Ver Logs em Tempo Real

```bash
# Todos os serviços
docker compose logs -f

# Serviço específico
docker compose logs -f honeypot
docker compose logs -f backend
```

### Reconstruir Imagens

```bash
docker compose up -d --build
```

### Limpar Tudo (incluindo volumes)

```bash
docker compose down -v
```

## Primeiros Passos no Dashboard

### 1. Dashboard Principal

- Visualize KPIs em tempo real
- Veja gráficos de eventos
- Monitore sessões do honeypot

### 2. Eventos

- Navegue por todos os eventos de segurança
- Filtre por severidade, tipo ou IP
- Veja mapeamento MITRE ATT&CK

### 3. Alertas

- Monitore alertas gerados
- Acknowledge alertas
- Filtre por status

### 4. Honeypot

- Veja sessões capturadas
- Analise credenciais coletadas
- Monitore comandos executados

### 5. Threat Hunting

- Execute buscas customizadas
- Analise IPs em detalhe
- Correlacione eventos

### 6. Relatórios

- Gere relatórios profissionais
- Exporte em Markdown, HTML ou PDF
- Inclua recomendações e IOCs

## Solução de Problemas

### Serviços Não Iniciam

```bash
# Verifique logs
docker compose logs

# Verifique se portas estão livres
netstat -tlnp | grep -E '3000|8000|2222|6379|9200|5432'
```

### Elasticsearch Não Conecta

```bash
# Verifique memória disponível
free -h

# Ajuste se necessário
sudo sysctl -w vm.max_map_count=262144
```

### Honeypot Não Recebe Conexões

```bash
# Verifique se porta 2222 está aberta
sudo netstat -tlnp | grep 2222

# Teste conexão local
ssh -p 2222 test@localhost
```

### Dashboard Não Carrega

```bash
# Verifique se backend está rodando
curl http://localhost:8000/health

# Verifique navegador console (F12)
```

## Próximos Passos

1. **Leia a documentação educacional:** `docs/SOC_EDUCATIONAL.md`
2. **Explore o MITRE ATT&CK:** Veja mapeamento automático
3. **Configure alertas:** Edite playbooks em `playbooks/executor.py`
4. **Customize detecções:** Ajuste regras em `backend/app/detector.py`
5. **Adicione tenants:** Simule ambiente multi-tenant

## Ambiente de Desenvolvimento

Para desenvolvimento local (sem Docker):

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

### Honeypot

```bash
cd honeypot
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python main.py
```

## Suporte

- 📚 **Documentação Completa:** Veja `README.md`
- 🎓 **Guia Educacional:** Veja `docs/SOC_EDUCATIONAL.md`
- 🐛 **Reporte Bugs:** Abra uma issue no repositório

---

> ⚠️ **Lembrete:** Esta plataforma é destinada **EXCLUSIVAMENTE** para ambientes laboratoriais e autorizados.

**Divirta-se aprendendo! 🛡️**
