import { useState } from 'react'
import api from '../services/api'

export default function Reports() {
  const [reportType, setReportType] = useState('executive')
  const [format, setFormat] = useState('markdown')
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState<any>(null)

  const generateReport = async () => {
    setLoading(true)
    
    try {
      const response = await api.post('/api/reports/generate', {
        report_type: reportType,
        format,
        include_recommendations: true,
        include_iocs: true
      })
      setReport(response.data)
    } catch (error) {
      console.error('Erro ao gerar relatório:', error)
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = () => {
    if (!report) return
    
    const extension = format === 'html' ? 'html' : format === 'pdf' ? 'pdf' : 'md'
    const blob = new Blob([report.content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `soc-report-${new Date().toISOString().split('T')[0]}.${extension}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <div className="header">
        <h2>Relatórios</h2>
      </div>

      <div className="grid-2">
        {/* Report Form */}
        <div className="card">
          <div className="card-header">
            <h3>Gerar Relatório</h3>
          </div>
          
          <div className="form-group">
            <label>Tipo de Relatório</label>
            <select value={reportType} onChange={(e) => setReportType(e.target.value)}>
              <option value="executive">Resumo Executivo</option>
              <option value="incidents">Incidentes Detalhados</option>
              <option value="honeypot">Análise de Honeypot</option>
              <option value="ioc">Indicadores de Comprometimento</option>
            </select>
          </div>

          <div className="form-group">
            <label>Formato</label>
            <select value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
              <option value="pdf">PDF</option>
            </select>
          </div>

          <button 
            className="btn btn-primary" 
            onClick={generateReport}
            disabled={loading}
          >
            {loading ? 'Gerando...' : 'Gerar Relatório'}
          </button>
        </div>

        {/* Report Preview */}
        {report && (
          <div className="card">
            <div className="card-header">
              <h3>Relatório Gerado</h3>
              <button className="btn btn-secondary" onClick={downloadReport}>
                Download
              </button>
            </div>
            
            <div style={{ maxHeight: '600px', overflow: 'auto' }}>
              {format === 'html' ? (
                <div dangerouslySetInnerHTML={{ __html: report.content }} />
              ) : (
                <pre style={{ 
                  background: 'var(--bg-secondary)', 
                  padding: '15px', 
                  borderRadius: '8px',
                  whiteSpace: 'pre-wrap',
                  wordWrap: 'break-word',
                  fontSize: '0.9rem',
                  lineHeight: '1.6'
                }}>
                  {report.content}
                </pre>
              )}
            </div>
            
            <p style={{ marginTop: '10px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Gerado em: {new Date(report.generated_at).toLocaleString('pt-BR')}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
