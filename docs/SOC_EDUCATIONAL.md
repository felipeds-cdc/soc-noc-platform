# 📚 Guia Educacional - SOC, SIEM, SOAR e NOC

> Este guia foi desenvolvido para profissionais que desejam compreender os fundamentos de operações de segurança e rede, técnicas de detecção e resposta a incidentes.

---

## 🔰 1. Como Funciona um SOC (Security Operations Center)

### O que é um SOC?

Um **Security Operations Center (SOC)** é uma equipe e infraestrutura centralizada responsável por **monitorar, detectar, analisar e responder** a incidentes de segurança cibernética em tempo real.

### Funções Principais do SOC

1. **Monitoramento Contínuo (24/7)**
   - Vigilância constante de redes, sistemas e aplicações
   - Coleta e análise de logs e eventos de segurança
   - Detecção de anomalias e comportamentos suspeitos

2. **Detecção de Ameaças**
   - Identificação de ataques em andamento
   - Correlação de eventos para detectar padrões complexos
   - Uso de inteligência de ameaças (Threat Intelligence)

3. **Triagem e Análise**
   - Classificação de alertas por severidade
   - Investigação de incidentes
   - Determinação do escopo e impacto

4. **Resposta a Incidentes**
   - Contenção de ameaças
   - Erradicação da causa raiz
   - Recuperação de sistemas afetados

5. **Relatórios e Melhoria Contínua**
   - Documentação de incidentes
   - Lições aprendidas
   - Aprimoramento de processos e regras de detecção

### Estrutura Típica de uma Equipe SOC

| Papel | Responsabilidades |
|-------|-------------------|
| **SOC Manager** | Gerencia equipe, processos e métricas |
| **Tier 1 Analyst** | Triagem inicial, classificação de alertas |
| **Tier 2 Analyst** | Investigação profunda, resposta a incidentes |
| **Tier 3 Analyst** | Threat hunting, análise forense avançada |
| **Security Engineer** | Manutenção de ferramentas e infraestrutura |

### Ferramentas Comuns de um SOC

- **SIEM**: Splunk, IBM QRadar, Elastic Security, Wazuh
- **EDR/XDR**: CrowdStrike, SentinelOne, Microsoft Defender
- **Network Monitoring**: Zeek, Suricata, Wireshark
- **Threat Intelligence**: MISP, AlienVault OTX
- **Ticketing**: Jira, ServiceNow, TheHive

---

## 🔍 2. Diferença Entre SIEM, SOAR e NOC

### SIEM (Security Information and Event Management)

**O que é:** Plataforma que **coleta, armazena, correlaciona e analisa** logs e eventos de segurança de diversas fontes.

**Funções Principais:**
- Coleta de logs de múltiplas fontes (firewalls, servidores, aplicações)
- Normalização e correlação de eventos
- Geração de alertas baseados em regras
- Dashboards e relatórios
- Conformidade e auditoria

**Exemplos:** Splunk, IBM QRadar, Elastic Security, Wazuh, LogRhythm

**Como funciona:**
```
[Fontes de Log] → [Coleta] → [Normalização] → [Correlação] → [Alertas]
                                                    ↓
                                              [Dashboard]
```

### SOAR (Security Orchestration, Automation and Response)

**O que é:** Plataforma que **automatiza e orquestra** respostas a incidentes de segurança, integrando diferentes ferramentas.

**Funções Principais:**
- Orquestração de ferramentas de segurança
- Automação de playbooks de resposta
- Gerenciamento de casos e incidentes
- Integração via APIs com outras ferramentas
- Redução do tempo de resposta (MTTR)

**Exemplos:** Palo Alto XSOAR, Splunk SOAR, Siemplify, Tines

**Exemplo de Playbook:**
```yaml
Trigger: Alerta de Brute Force SSH
Ações:
  1. Bloquear IP no firewall automaticamente
  2. Criar ticket no sistema de incidentes
  3. Notificar analista via Slack
  4. Coletar logs do sistema afetado
  5. Verificar se há outros IPs relacionados
  6. Gerar relatório do incidente
```

### NOC (Network Operations Center)

**O que é:** Equipe responsável por **monitorar e manter a infraestrutura de rede** e garantir disponibilidade e performance.

**Funções Principais:**
- Monitoramento de disponibilidade de rede
- Performance e capacidade (capacity planning)
- Gerenciamento de falhas de hardware
- Configuração de dispositivos de rede
- Otimização de performance

**Diferenças SOC vs NOC:**

| Aspecto | SOC | NOC |
|---------|-----|-----|
| **Foco** | Segurança | Disponibilidade |
| **Monitora** | Ameaças, ataques | Uptime, performance |
| **Métricas** | MTTR, MTTD | SLA, uptime % |
| **Responde a** | Incidentes de segurança | Falhas de rede |
| **Ferramentas** | SIEM, EDR | Nagios, Zabbix, PRTG |

### Convergência SOC + NOC

Organizações modernas estão integrando SOC e NOC para:
- Visão unificada de operações
- Detecção de ataques que afetam disponibilidade
- Resposta coordenada a incidentes
- Redução de custos operacionais

---

## 🛡️ 3. Técnicas de Detecção

### 3.1 Detecção Baseada em Assinatura

**Como funciona:** Compara eventos com padrões conhecidos de ataque.

**Exemplos:**
- Regex para detectar brute force: `Failed password for .* from (\d+\.\d+\.\d+\.\d+)`
- Detecção de SQL Injection: `SELECT.*FROM.*WHERE`
- Padrões de malware: hashes MD5/SHA256 conhecidos

**Vantagens:**
- ✅ Baixo índice de falsos positivos
- ✅ Fácil de implementar
- ✅ Eficaz contra ameaças conhecidas

**Desvantagens:**
- ❌ Não detecta ataques novos (zero-day)
- ❌ Requer atualização constante
- ❌ Não detecta variações de ataques

### 3.2 Detecção Baseada em Anomalia

**Como funciona:** Estabelece linha de base do comportamento normal e alerta sobre desvios.

**Técnicas:**
- **Estatística**: Desvio padrão, média móvel
- **Machine Learning**: Isololation Forest, One-Class SVM
- **Comportamental**: Perfis de usuário, horários de acesso

**Exemplo:**
```python
# Detecta login fora do horário habitual
if login_time not in user.normal_hours:
    alert("Login em horário incomum")
    
# Detecta volume anormal de tráfego
if traffic > baseline + (3 * std_dev):
    alert("Pico de tráfego anômalo")
```

**Vantagens:**
- ✅ Detecta ataques desconhecidos
- ✅ Adapta-se a mudanças
- ✅ Identifica insider threats

**Desvantagens:**
- ❌ Maior taxa de falsos positivos
- ❌ Período de aprendizado necessário
- ❌ Complexidade de implementação

### 3.3 Detecção Baseada em Comportamento (UEBA)

**User and Entity Behavior Analytics**

Analisa padrões de comportamento de usuários e entidades para detectar desvios.

**Exemplos de detecções:**
- Usuário acessando sistemas nunca antes utilizados
- Volume de downloads incomum
- Acessos de localizações geográficas impossíveis (impossible travel)
- Privilégios elevados repentinamente utilizados

### 3.4 Correlação de Eventos

**Como funciona:** Combina múltiplos eventos para identificar padrões complexos de ataque.

**Exemplo de correlação - Kill Chain:**
```
1. Port Scan detectado (Reconhecimento)
2. Tentativa de exploração (Weaponization)
3. Login bem-sucedido após múltiplas falhas (Brute Force)
4. Download de arquivos sensíveis (Exfiltração)

→ Alerta correlacionado: Ataque em andamento
```

### 3.5 Técnicas Específicas de Detecção

#### Brute Force SSH

```python
# Regra de detecção
failed_attempts = count_events(
    event_type="auth_failure",
    source_ip=ip,
    time_window="5m"
)

if failed_attempts >= 5:
    create_alert(
        severity="high",
        rule="SSH Brute Force Detected",
        mitre_technique="T1110"
    )
```

#### Port Scanning

```python
# Detecção de scan
unique_ports = count_unique(
    field="destination_port",
    source_ip=ip,
    time_window="1m"
)

if unique_ports >= 20:
    create_alert(
        severity="medium",
        rule="Port Scan Detected",
        mitre_technique="T1046"
    )
```

#### Data Exfiltration

```python
# Detecção de exfiltração
outbound_traffic = sum(
    field="bytes_sent",
    source_ip=internal_ip,
    destination=external_ip,
    time_window="1h"
)

if outbound_traffic > threshold:
    create_alert(
        severity="critical",
        rule="Possible Data Exfiltration",
        mitre_technique="T1041"
    )
```

#### Lateral Movement

```python
# Movimento lateral
unique_destinations = count_unique(
    field="destination_ip",
    source_ip=compromised_host,
    time_window="30m"
)

if unique_destinations > 5:
    create_alert(
        severity="high",
        rule="Possible Lateral Movement",
        mitre_technique="T1021"
    )
```

---

## 🎯 4. MITRE ATT&CK Framework

### O que é?

O **MITRE ATT&CK** (Adversarial Tactics, Techniques, and Common Knowledge) é uma base de conhecimento global de táticas e técnicas usadas por adversários.

### Estrutura

**Táticas** (O QUÊ o atacante quer fazer):
- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Lateral Movement
- Collection
- Command and Control
- Exfiltration
- Impact

**Técnicas** (COMO o atacante faz):
- T1110: Brute Force
- T1046: Network Service Scanning
- T1059: Command and Scripting Interpreter
- T1078: Valid Accounts

### Mapeamento na Plataforma

Nossa plataforma mapeia automaticamente eventos detectados para técnicas MITRE ATT&CK:

| Evento | Técnica MITRE | Tática |
|--------|---------------|--------|
| Brute Force SSH | T1110 | Credential Access |
| Port Scan | T1046 | Discovery |
| Comando suspeito | T1059 | Execution |
| Login com credenciais roubadas | T1078 | Initial Access |

---

## 📊 5. Métricas e KPIs de SOC

### Métricas Essenciais

| Métrica | Descrição | Meta |
|---------|-----------|------|
| **MTTD** (Mean Time to Detect) | Tempo médio para detectar uma ameaça | < 1 hora |
| **MTTR** (Mean Time to Respond) | Tempo médio para responder a um incidente | < 4 horas |
| **Alert Volume** | Número total de alertas por período | Monitorar tendência |
| **False Positive Rate** | % de alertas que são falsos positivos | < 10% |
| **Coverage** | % de ativos monitorados | > 95% |

### KPIs do Dashboard

- **Total de Eventos**: Volume total de eventos de segurança
- **Alertas Críticos/Altos**: Requerem atenção imediata
- **IPs Únicos**: Diversidade de fontes de ataque
- **Sessões Honeypot**: Eficácia da coleta de ameaças
- **Tentativas Brute Force**: Indicador de ataques automatizados

---

## 🔬 6. Threat Hunting

### O que é?

**Threat Hunting** é a prática de buscar proativamente ameaças que passaram pelas defesas automatizadas.

### Metodologia

1. **Hipótese**: "Atores maliciosos podem estar usando credenciais válidas"
2. **Investigação**: Buscar logs de autenticação por anomalias
3. **Descoberta**: Identificar padrões suspeitos
4. **Resposta**: Investigar e mitigar
5. **Melhoria**: Criar detecções automatizadas

### Técnicas de Hunting

- **Busca por IOCs**: IPs, hashes, domínios conhecidos como maliciosos
- **Análise de Comportamento**: Desvios de padrões normais
- **Stack Counting**: Identificar valores raros em grandes datasets
- **Grouping**: Agrupar eventos similares para identificar padrões

### Exemplo de Query de Hunting

```
# Buscar logins fora do horário comercial
source:auth AND status:success AND time:[18h TO 06h]

# Buscar múltiplas falhas seguidas de sucesso
source:auth AND status:failure | stats count by source_ip | where count > 10
```

---

## 🚨 7. Resposta a Incidentes

### Fases do Incident Response (NIST)

1. **Preparação**
   - Políticas e procedimentos
   - Ferramentas e treinamento
   - Planos de comunicação

2. **Detecção e Análise**
   - Identificação do incidente
   - Triagem e priorização
   - Escopo e impacto

3. **Contenção, Erradicação e Recuperação**
   - Isolar sistemas afetados
   - Remover causa raiz
   - Restaurar serviços

4. **Pós-Incidente**
   - Lições aprendidas
   - Relatório final
   - Melhorias de segurança

### Playbooks Automatizados

Nossa plataforma implementa playbooks automatizados:

```yaml
Playbook: Brute Force Response
Trigger: Alert severity >= high AND event_type = brute_force

Actions:
  - type: block_ip
    params:
      firewall: primary
      duration: 3600
      
  - type: notify
    params:
      channels: [slack, email]
      severity: high
      
  - type: create_ticket
    params:
      system: jira
      priority: P2
      
  - type: collect_evidence
    params:
      sources: [auth.log, syslog, honeypot]
      timeframe: 1h
      
  - type: enrich_ioc
    params:
      ip: ${event.source_ip}
      feeds: [virustotal, abuseipdb]
```

---

## 📖 8. Glossário

| Termo | Definição |
|-------|-----------|
| **IOC** | Indicator of Compromise - Evidência de comprometimento |
| **IOA** | Indicator of Attack - Sinal de ataque em andamento |
| **TTP** | Tactics, Techniques and Procedures - Padrões do atacante |
| **False Positive** | Alerta triggered por atividade legítima |
| **False Negative** | Ataque real que não foi detectado |
| **Dwell Time** | Tempo entre invasão e detecção |
| **Zero-Day** | Vulnerabilidade desconhecida pelo vendor |
| **Red Team** | Equipe que simula ataques |
| **Blue Team** | Equipe de defesa (SOC) |
| **Purple Team** | Colaboração entre Red e Blue Team |

---

## 🎓 9. Referências e Estudos Adicionais

### Certificações Recomendadas
- **CompTIA Security+**: Fundamentos de segurança
- **GIAC (GCIH, GCIA)**: Incident handling e análise
- **CySA+**: Cybersecurity Analyst
- **CISSP**: Gestão de segurança

### Recursos Online
- MITRE ATT&CK: https://attack.mitre.org
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- SANS Internet Storm Center: https://isc.sans.edu
- AlienVault OTX: https://otx.alienvault.com

### Ferramentas para Praticar
- TryHackMe: https://tryhackme.com
- HackTheBox: https://www.hackthebox.com
- Blue Team Labs Online: https://blueteamlabs.online

---

> ⚠️ **Lembre-se**: Todo conhecimento de segurança deve ser usado **eticamente** e apenas em **ambientes autorizados**. Acesso não autorizado a sistemas é crime na maioria das jurisdições.

---

*Documento desenvolvido para fins educacionais - SOC/NOC Platform*
