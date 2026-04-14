"""
Endpoints de relatórios
"""
from fastapi import APIRouter, Depends, Request
from datetime import datetime
import uuid
import markdown

from app.models import ReportRequest, ReportResponse
from app.security import get_current_user, require_analyst_or_admin

router = APIRouter(prefix="/api/reports", tags=["Reports"])


@router.post("/generate", response_model=ReportResponse)
async def generate_report(
    report_data: ReportRequest,
    request: Request,
    current_user: dict = Depends(require_analyst_or_admin)
):
    """Gera relatório profissional."""
    from fastapi import HTTPException
    es_client = request.app.state.es_client
    try:
        start_time = report_data.start_time or datetime.utcnow().replace(hour=0, minute=0, second=0)
        end_time = report_data.end_time or datetime.utcnow()

        events_count = await es_client.count(index="soc_events",
            query={"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}})
        severity_agg = await es_client.search(index="soc_events", size=0,
            query={"range": {"timestamp": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}},
            aggs={"by_severity": {"terms": {"field": "severity"}}, "by_type": {"terms": {"field": "event_type", "size": 10}},
                  "by_ip": {"terms": {"field": "source_ip", "size": 20}}, "by_country": {"terms": {"field": "geo_country", "size": 10}}})
        honeypot_sessions = await es_client.count(index="honeypot_sessions",
            query={"range": {"started_at": {"gte": start_time.isoformat(), "lte": end_time.isoformat()}}})

        aggs = severity_agg.get('aggregations', {})

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

        md_content += "\n### Tipos de Eventos Mais Frequentes\n\n| Tipo de Evento | Contagem |\n|----------------|----------|\n"
        for bucket in aggs.get('by_type', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"

        md_content += "\n### Top IPs de Origem\n\n| IP | Contagem |\n|----|----------|\n"
        for bucket in aggs.get('by_ip', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"

        md_content += "\n### Distribuição Geográfica\n\n| País | Contagem |\n|------|----------|\n"
        for bucket in aggs.get('by_country', {}).get('buckets', []):
            md_content += f"| {bucket['key']} | {bucket['doc_count']} |\n"

        if report_data.include_recommend:
            md_content += """
## Recomendações de Segurança

1. **Monitoramento Contínuo:** Manter sistemas de detecção ativos 24/7
2. **Análise de Tendências:** Revisar relatórios semanalmente
3. **Atualização de Regras:** Atualizar regras de detecção baseadas em novos padrões
4. **Hardening:** Reforçar configurações de sistemas expostos
5. **Threat Intelligence:** Integrar feeds de inteligência de ameaças

---
*Relatório gerado automaticamente pela SOC/NOC Platform*  
*⚠️ Este relatório é confidencial e destinado apenas para uso autorizado*
"""

        content = md_content
        if report_data.format == "html":
            content = markdown.markdown(md_content, extensions=['tables', 'fenced_code'])
            content = f"""<!DOCTYPE html><html><head><title>Relatório SOC/NOC</title>
<style>body{{font-family:Arial,sans-serif;margin:40px;line-height:1.6}}h1{{color:#2c3e50;border-bottom:3px solid #3498db;padding-bottom:10px}}
table{{border-collapse:collapse;width:100%;margin:20px 0}}th,td{{border:1px solid #ddd;padding:12px;text-align:left}}
th{{background-color:#3498db;color:white}}tr:nth-child(even){{background-color:#f2f2f2}}</style>
</head><body>{content}</body></html>"""
        elif report_data.format == "pdf":
            content = f"<h1>Para gerar PDF, instale weasyprint</h1>{markdown.markdown(md_content, extensions=['tables'])}"

        return ReportResponse(report_id=str(uuid.uuid4()), report_type=report_data.report_type,
            format=report_data.format, generated_at=datetime.utcnow(), content=content)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro ao gerar relatório: {str(e)}")


@router.get("/templates")
async def get_report_templates(current_user: dict = Depends(get_current_user)):
    """Obtém templates de relatórios disponíveis."""
    return {"templates": [
        {"id": "executive", "name": "Resumo Executivo", "description": "Visão geral para gestão"},
        {"id": "incidents", "name": "Incidentes Detalhados", "description": "Análise detalhada de incidentes"},
        {"id": "honeypot", "name": "Análise de Honeypot", "description": "Ataques capturados pelo honeypot"},
        {"id": "ioc", "name": "Indicadores de Comprometimento", "description": "IOCs detectados no período"},
    ]}
