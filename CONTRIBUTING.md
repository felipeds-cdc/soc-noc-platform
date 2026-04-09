# 🤝 Contribuindo com o SOC/NOC Platform

Obrigado pelo interesse em contribuir com a plataforma SOC/NOC! Este documento fornece diretrizes para contribuições.

## 📋 Como Contribuir

### 1. Reportando Bugs

Use o issue tracker com:

- **Título descritivo** do problema
- **Passos para reproduzir** o bug
- **Comportamento esperado** vs. observado
- **Logs e screenshots** (se aplicável)
- **Ambiente** (OS, Docker version, etc.)

### 2. Sugerindo Melhorias

- Descreva a funcionalidade desejada
- Explique o caso de uso
- Considere implementações alternativas
- Seja específico sobre o valor agregado

### 3. Pull Requests

#### Preparação

1. Fork o repositório
2. Crie uma branch para sua feature: `git checkout -b feature/nome-da-feature`
3. Mantenha commits atômicos e bem descritos
4. Teste suas mudanças localmente

#### Padrões de Código

**Python:**
- Siga PEP 8
- Use type hints
- Documente funções e classes
- Mantenha funções com responsabilidade única

**TypeScript/React:**
- Use functional components com hooks
- Tipagem estrita
- Componentes com responsabilidade única
- Nomeie componentes em PascalCase

**Commits:**
```
feat: adiciona detecção de brute force
fix: corrige parsing de logs
docs: atualiza documentação educacional
refactor: otimiza motor de correlação
```

### 4. Áreas que Precisam de Ajuda

#### Alta Prioridade
- [ ] Testes unitários e de integração
- [ ] Suporte a mais fontes de logs
- [ ] Integração com Wazuh
- [ ] Detecção de anomalias com ML
- [ ] Mais playbooks automatizados

#### Média Prioridade
- [ ] Internacionalização (i18n)
- [ ] Tema claro/escuro no dashboard
- [ ] Exportação de dados (CSV, JSON)
- [ ] API GraphQL
- [ ] Mobile responsive improvements

#### Baixa Prioridade
- [ ] Plugin system
- [ ] Custom dashboards
- [ ] Alert routing avançado
- [ ] Multi-language support

## 🔧 Arquitetura do Projeto

### Componentes Principais

```
soc-noc-platform/
├── backend/          # FastAPI - API REST
├── frontend/         # React + TypeScript - Dashboard
├── honeypot/         # Python + asyncssh - Honeypot SSH
├── agents/           # Python - Coletores de logs
├── processor/        # Python - Pipeline de eventos
├── simulator/        # Python - Simulador de ataques
├── playbooks/        # Python - Automação de resposta
├── mitre_attack/     # Python - Mapeamento ATT&CK
└── docker/           # Configurações Docker
```

### Fluxo de Dados

```
[Fontes] → Redis Streams → Processor → Elasticsearch/PostgreSQL
                                                    ↓
                                              Backend API
                                                    ↓
                                               Frontend
```

## 🧪 Testes

### Executando Testes

```bash
# Backend
cd backend
pytest

# Frontend
cd frontend
npm test
```

### Cobertura de Testes

Mantenha cobertura > 80% para novas features.

## 📝 Documentação

### Tipos de Documentação

1. **README.md** - Visão geral do projeto
2. **QUICKSTART.md** - Guia de início rápido
3. **docs/SOC_EDUCATIONAL.md** - Conteúdo educacional
4. **Docstrings** - Documentação de código
5. **Comments** - Explicações de lógica complexa

### Padrão de Docstrings

```python
def example_function(param1: str, param2: int) -> dict:
    """
    Descrição curta da função.
    
    Args:
        param1: Descrição do parâmetro
        param2: Descrição do parâmetro
        
    Returns:
        Descrição do retorno
        
    Raises:
        ExceptionType: Quando isso acontece
    """
    pass
```

## 🎯 Roadmap

### Versão 1.0 (Atual)
- ✅ Honeypot SSH funcional
- ✅ Coleta de logs básica
- ✅ Dashboard com KPIs
- ✅ API REST completa
- ✅ Relatórios automatizados
- ✅ MITRE ATT&CK mapping
- ✅ Playbooks básicos
- ✅ Simulador de ataques

### Versão 1.1 (Próxima)
- [ ] Testes unitários
- [ ] Integração Wazuh
- [ ] Detecção de anomalias
- [ ] Melhorias no dashboard
- [ ] Tema claro/escuro

### Versão 2.0
- [ ] Machine Learning para detecção
- [ ] Plugin system
- [ ] API GraphQL
- [ ] Mobile app
- [ ] Multi-tenant real

## 💡 Dicas para Contribuidores

1. **Comece pequeno:** Issues marcadas como `good-first-issue`
2. **Comunique-se:** Discuta mudanças grandes antes de implementar
3. **Teste:** Sempre teste localmente antes de submeter
4. **Documente:** Atualize documentação quando necessário
5. **Revise:** Revise PRs de outros contribuidores
6. **Seja respeitoso:** Siga o código de conduta

## 📜 Código de Conduta

### Nossos Padrões

✅ **Seja respeitoso** com todos os contribuidores  
✅ **Seja construtivo** em críticas e sugestões  
✅ **Seja paciente** com revisões e respostas  
✅ **Seja inclusivo** com diferentes níveis de experiência  

### Inaceitável

❌ Comentários ofensivos ou discriminatórios  
❌ Assédio de qualquer forma  
❌ Spam ou self-promotion excessivo  
❌ Uso inadequado do issue tracker  

## 🆘 Precisa de Ajuda?

- **Dúvidas técnicas:** Abra uma issue
- **Discussões:** Use discussions do GitHub
- **Documentação:** Veja docs e wiki
- **Chat:** Canal no Discord/Slack (se disponível)

## 🙏 Agradecimentos

Obrigado a todos que contribuem para tornar este projeto melhor!

---

*Última atualização: Abril 2026*
