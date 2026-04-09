import { useState } from 'react'
import api from '../services/api'

export default function ThreatHunting() {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<any>(null)
  const [loading, setLoading] = useState(false)
  const [ipAnalysis, setIpAnalysis] = useState<any>(null)
  const [searchIp, setSearchIp] = useState('')

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    
    try {
      const response = await api.post('/api/threat-hunting/search', {
        query,
        time_range: '24h'
      })
      setResults(response.data)
    } catch (error) {
      console.error('Erro na busca:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleIpAnalysis = async () => {
    if (!searchIp) return
    
    try {
      const response = await api.get(`/api/threat-hunting/ip-analysis/${searchIp}`)
      setIpAnalysis(response.data)
    } catch (error) {
      console.error('Erro na análise de IP:', error)
    }
  }

  return (
    <div>
      <div className="header">
        <h2>Threat Hunting</h2>
      </div>

      {/* Query Search */}
      <div className="card">
        <div className="card-header">
          <h3>Busca Customizada</h3>
        </div>
        <form onSubmit={handleSearch}>
          <div className="form-group">
            <label>Query (Elasticsearch Query String ou Lucene)</label>
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='severity:high AND source_ip:"10.0.0.*"'
              rows={3}
              style={{ fontFamily: 'monospace' }}
            />
          </div>
          <button type="submit" className="btn btn-primary" disabled={loading || !query}>
            {loading ? 'Buscando...' : 'Buscar'}
          </button>
        </form>

        {results && (
          <div style={{ marginTop: '20px' }}>
            <p>
              <strong>{results.total_hits}</strong> resultados encontrados 
              em {results.execution_time_ms.toFixed(0)}ms
            </p>
            <div style={{ maxHeight: '400px', overflow: 'auto', marginTop: '10px' }}>
              <pre style={{ background: 'var(--bg-secondary)', padding: '15px', borderRadius: '8px', fontSize: '0.85rem' }}>
                {JSON.stringify(results.results.slice(0, 10), null, 2)}
              </pre>
            </div>
          </div>
        )}
      </div>

      {/* IP Analysis */}
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
          <button className="btn btn-primary" onClick={handleIpAnalysis}>
            Analisar
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
                <div className="kpi-value" style={{ fontSize: '1.5rem' }}>
                  {ipAnalysis.geo_info?.country || 'N/A'}
                </div>
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
                    {Object.entries(ipAnalysis.event_types).map(([type, count]: [string, any]) => (
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
                <div style={{ background: 'var(--bg-secondary)', padding: '15px', borderRadius: '8px', maxHeight: '300px', overflow: 'auto' }}>
                  {ipAnalysis.commands_executed.map((cmd: string, idx: number) => (
                    <div key={idx} style={{ fontFamily: 'monospace', marginBottom: '5px' }}>
                      {cmd}
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
