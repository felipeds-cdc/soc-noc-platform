import { useMemo, useState } from 'react'
import toast from 'react-hot-toast'
import { generateSecurityReport, type GeneratedReport } from '../services/reportsService'
import { getErrorMessage } from '../services/error'

function sanitizeHtml(html: string): string {
  const parser = new DOMParser()
  const documentNode = parser.parseFromString(html, 'text/html')

  documentNode.querySelectorAll('script, iframe, object, embed, style').forEach((node) => node.remove())

  documentNode.querySelectorAll('*').forEach((element) => {
    Array.from(element.attributes).forEach((attribute) => {
      const name = attribute.name.toLowerCase()
      const value = attribute.value.toLowerCase()

      if (name.startsWith('on')) {
        element.removeAttribute(attribute.name)
      }

      if ((name === 'href' || name === 'src') && value.startsWith('javascript:')) {
        element.removeAttribute(attribute.name)
      }
    })
  })

  return documentNode.body.innerHTML
}

export default function Reports() {
  const [reportType, setReportType] = useState('executive')
  const [format, setFormat] = useState('markdown')
  const [loading, setLoading] = useState(false)
  const [report, setReport] = useState<GeneratedReport | null>(null)

  const generateReport = async () => {
    setLoading(true)

    try {
      const response = await generateSecurityReport({
        report_type: reportType,
        format,
        include_recommendations: true,
        include_iocs: true,
      })

      setReport(response)
      toast.success('Relatório gerado com sucesso.')
    } catch (requestError) {
      toast.error(getErrorMessage(requestError, 'Erro ao gerar relatório.'))
    } finally {
      setLoading(false)
    }
  }

  const safeHtml = useMemo(() => {
    if (format !== 'html' || !report?.content) {
      return ''
    }

    return sanitizeHtml(report.content)
  }, [format, report?.content])

  const downloadReport = () => {
    if (!report) {
      return
    }

    const extension = format === 'html' ? 'html' : format === 'pdf' ? 'pdf' : 'md'
    const mimeType = extension === 'html' ? 'text/html' : 'text/plain'
    const blob = new Blob([report.content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')

    anchor.href = url
    anchor.download = `soc-report-${new Date().toISOString().split('T')[0]}.${extension}`
    anchor.click()

    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <div className="header">
        <h2>Relatórios</h2>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3>Gerar Relatório</h3>
          </div>

          <div className="form-group">
            <label htmlFor="report-type">Tipo de Relatório</label>
            <select id="report-type" value={reportType} onChange={(e) => setReportType(e.target.value)}>
              <option value="executive">Resumo Executivo</option>
              <option value="incidents">Incidentes Detalhados</option>
              <option value="honeypot">Análise de Honeypot</option>
              <option value="ioc">Indicadores de Comprometimento</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="report-format">Formato</label>
            <select id="report-format" value={format} onChange={(e) => setFormat(e.target.value)}>
              <option value="markdown">Markdown</option>
              <option value="html">HTML</option>
              <option value="pdf">PDF</option>
            </select>
          </div>

          <button className="btn btn-primary" onClick={generateReport} disabled={loading}>
            {loading ? 'Gerando...' : 'Gerar Relatório'}
          </button>
        </div>

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
                <div dangerouslySetInnerHTML={{ __html: safeHtml }} />
              ) : (
                <pre
                  style={{
                    background: 'var(--bg-secondary)',
                    padding: '15px',
                    borderRadius: '8px',
                    whiteSpace: 'pre-wrap',
                    wordWrap: 'break-word',
                    fontSize: '0.9rem',
                    lineHeight: '1.6',
                  }}
                >
                  {report.content}
                </pre>
              )}
            </div>

            <p style={{ marginTop: '10px', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              Gerado em: {report.generated_at ? new Date(report.generated_at).toLocaleString('pt-BR') : 'N/A'}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
