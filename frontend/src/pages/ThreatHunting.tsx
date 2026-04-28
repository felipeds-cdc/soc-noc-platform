import { useState } from 'react'
import toast from 'react-hot-toast'
import { analyzeIpAddress, searchThreats, type IpAnalysis, type ThreatSearchResponse } from '../services/threatHuntingService'
import { getErrorMessage } from '../services/error'

export default function ThreatHunting() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<ThreatSearchResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [ipAnalysis, setIpAnalysis] = useState<IpAnalysis | null>(null)
  const [searchIp, setSearchIp] = useState('')
  const [analyzingIp, setAnalyzingIp] = useState(false)

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    const safeQuery = query.trim()
    if (!safeQuery) {
      toast.error('Informe uma query para buscar.')
      return
    }

    setLoading(true)

    try {
      const response = await searchThreats(safeQuery)
      setResults(response)
    } catch (requestError) {
      toast.error(getErrorMessage(requestError, 'Erro ao executar busca de threat hunting.'))
    } finally {
      setLoading(false)
    }
  }

  const handleIpAnalysis = async () => {
    const ip = searchIp.trim()
    if (!ip) {
      toast.error('Informe um IP para análise.')
      return
    }

    setAnalyzingIp(true)

    try {
      const response = await analyzeIpAddress(ip)
      setIpAnalysis(response)
    } catch (requestError) {
      toast.error(getErrorMessage(requestError, 'Erro ao analisar IP.'))
    } finally {
      setAnalyzingIp(false)
    }
  }

  return (
    <div>
      <div className="header">
        <h2>Threat Hunting</h2>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Busca Customizada</h3>
        </div>
        <form onSubmit={handleSearch}>
          <div className="form-group">
            <label htmlFor="threat-query">Query (Elasticsearch Query String ou Lucene)</label>
            <textarea
              id="threat-query"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='severity:high AND source_ip:"10.0.0.*"'
              rows={3}
              style={{ fontFamily: 'monospace' }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading || !query.trim()}>
            {loading ? 'Buscando...' : 'Buscar'}
          </button>
        </form>

        {results && (
          <div style={{ marginTop: '20px' }}>
            <p>
              <strong>{results.total_hits}</strong> resultados encontrados em {results.execution_time_ms.toFixed(0)}ms
            </p>
            <div style={{ maxHeight: '400px', overflow: 'auto', marginTop: '10px' }}>
              <pre style={{ background: 'var(--bg-secondary)', padding: '15px', borderRadius: '8px', fontSize: '0.85rem' }}>
                {JSON.stringify(results.results.slice(0, 10), null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Análise de IP</h3>
        </div>
        <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
          <input
            type="text"
            value={searchIp}
            onChange={(e) => setSearchIp(e.target.value)}
            placeholder="192.168.1.100"
            style={{ flex: 1 }}
          />
          <button className="btn btn-primary" onClick={handleIpAnalysis} disabled={analyzingIp}>
            {analyzingIp ? 'Analisando...' : 'Analisar'}
          </button>
        </div>

        {ipAnalysis && (
          <div>
            <div className="kpi-grid" style={{ marginBottom: '20px' }}>
              <div className="kpi-card">
                <div className="kpi-label">Total de Eventos</div>
                <div className="kpi-value">{ipAnalysis.total_events}</div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">Sessões Honeypot</div>
                <div className="kpi-value">{ipAnalysis.associated_sessions}</div>
              </div>
              <div className="kpi-card">
                <div className="kpi-label">País</div>
                <div className="kpi-value" style={{ fontSize: '1.5rem' }}>{ipAnalysis.geo_info?.country || 'N/A'}</div>
              </div>
            </div>

            {ipAnalysis.event_types && Object.keys(ipAnalysis.event_types).length > 0 && (
              <div style={{ marginBottom: '20px' }}>
                <h4>Distribuição por Tipo de Evento</h4>
                <table>
                  <thead>
                    <tr>
                      <th>Tipo</th>
                      <th>Contagem</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(ipAnalysis.event_types).map(([type, count]) => (
                      <tr key={type}>
                        <td>{type}</td>
                        <td>{count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {ipAnalysis.commands_executed && ipAnalysis.commands_executed.length > 0 && (
              <div>
                <h4>Comandos Executados ({ipAnalysis.commands_executed.length})</h4>
                <div
                  style={{
                    background: 'var(--bg-secondary)',
                    padding: '15px',
                    borderRadius: '8px',
                    maxHeight: '300px',
                    overflow: 'auto',
                  }}
                >
                  {ipAnalysis.commands_executed.map((command, index) => (
                    <div key={`${command}-${index}`} style={{ fontFamily: 'monospace', marginBottom: '5px' }}>
                      {command}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
