"""
Endpoints de relatórios
"""
from fastapi import APIRouter, Depends, Query
from typing import Optional
from datetime import datetime
import uuid
import markdown
from jinja2 import Template

from app.models import ReportRequest, ReportResponse
from app.security import get_current_user, require_analyst_or_admin
from app.database import get_db

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    report_data: ReportRequest,
    db=Depends(get_db),
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Gera relatório profissional."""
    from elasticsearch import AsyncElasticsearch
    from app.config import get_settings
    
    settings = get_settings()
    es = AsyncElasticsearch([settings.ELASTICSEARCH_URL])
    
    try:
        start_time = report_data.start_time or datetime.utcnow().replace(hour=0, minute=0, second=0)
        end_time = report_data.end_time or datetime.utcnow()
        
        # Coleta dados para o relatório
        events_count = await es.count(
            index="soc_events",
            query={"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        )
        
        severity_agg = await es.search(
            index="soc_events",
            size=0,
            query={"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            aggs={
                "by_severity": {"terms": {"field": "severity"}},
                "by_type": {"terms": {"field": "event_type", "size": 10}},
                "by_ip": {"terms": {"field": "source_ip", "size": 20}},
                "by_country": {"terms": {"field": "geo_country", "size": 10}}
            }
        )
        
        honeypot_sessions = await es.count(
            index="honeypot_sessions",
            query={"range": {"started_at": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}}
        )
        
        aggs = severity_agg.get('aggregations', {})
        
        # Gera conteúdo Markdown
        md_content = f"""# Relatório de Segurança - SOC/NOC Platform

## Resumo Executivo

**Período:** {start_time.strftime('%d/%m/%Y %H:%M')} - {end_time.strftime('%d/%m/%Y %H:%M')}  
**Gerado em:** {datetime.utcnow().strftime('%d/%m/%Y %H:%M:%S')} UTC  
**Gerado por:** {current_user['username']}

### Visão Geral

- **Total de Eventos:** {events_count.get('count', 0)}
- **Sessões Honeypot:** {honeypot_sessions.get('count', 0)}

### Distribuição por Severidade

| Severidade | Contagem |
|------------|----------|
"""
        for bucket in aggs.get('by_severity', {}).get('buckets', []):
            md_content += f"| {bucket['key'].upper()} | {bucket['doc_count']} |\n"
            
        md_content += f"""
### Tipos de Eventos Mais Frequentes

| Tipo de Evento | Contagem |
|----------------|----------|
"""
        for bucket in aggs.get('by_type', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"
            
        md_content += f"""
### Top IPs de Origem

| IP | Contagem |
|----|----------|
"""
        for bucket in aggs.get('by_ip', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"
            
        md_content += f"""
### Distribuição Geográfica

| País | Contagem |
|------|----------|
"""
        for bucket in aggs.get('by_country', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"
            
        if report_data.include_recommend:
            md_content += f"""
## Recomendações de Segurança

1. **Monitoramento Contínuo:** Manter sistemas de detecção ativos 24/7
2. **Análise de Tendências:** Revisar relatórios semanalmente
3. **Atualização de Regras:** Atualizar regras de detecção baseadas em novos padrões
4. **Hardening:** Reforçar configurações de sistemas expostos
5. **Threat Intelligence:** Integrar feeds de inteligência de ameaças

## Indicadores de Comprometimento (IOCs)

Os seguintes indicadores foram identificados durante o período:

- IPs maliciosos detectados: {len(aggs.get('by_ip', {}).get('buckets', []))}
- Técnicas MITRE ATT&CK mapeadas: Ver análise detalhada
- Credenciais comprometidas capturadas: Consultar base de honeypot

---

*Relatório gerado automaticamente pela SOC/NOC Platform*  
*⚠️ Este relatório é confidencial e destinado apenas para uso autorizado*
"""
        
        # Converte para formato solicitado
        content = md_content
        if report_data.format == "html":
            content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
            content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Relatório SOC/NOC - {datetime.utcnow().strftime('%d/%m/%Y')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        h1 {{ color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }}
        h2 {{ color: #34495e; margin-top: 30px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #3498db; color: white; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
        .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.9em; }}
    </style>
</head>
<body>
{content}
<div class="footer">
    <p>⚠️ Documento confidencial - SOC/NOC Platform</p>
</div>
</body>
</html>
"""
        elif report_data.format == "pdf":
            # Em produção, usar weasyprint ou similar
            html_content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
            content = f"<h1>Para gerar PDF, instale weasyprint</h1>{html_content}"
            
        return ReportResponse(
            report_id=str(uuid.uuid4()),
            report_type=report_data.report_type,
            format=report_data.format,
            generated_at=datetime.utcnow(),
            content=content
        )
        
    finally:
        await es.close()


@router.get("/templates")
async def get_report_templates(
    current_user: dict = Depends(get_current_user)
):
    """Obtém templates de relatórios disponíveis."""
    return {
        "templates": [
            {"id": "executive", "name": "Resumo Executivo", "description": "Visão geral para gestão"},
            {"id": "incidents", "name": "Incidentes Detalhados", "description": "Análise detalhada de incidentes"},
            {"id": "honeypot", "name": "Análise de Honeypot", "description": "Ataques capturados pelo honeypot"},
            {"id": "ioc", "name": "Indicadores de Comprometimento", "description": "IOCs detectados no período"},
        ]
    }
