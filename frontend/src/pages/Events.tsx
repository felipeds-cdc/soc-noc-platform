import { useState, useEffect } from 'react'
import api from '../services/api'

export default function Events() {
  const [events, setEvents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState({
    severity: '',
    event_type: '',
    source_ip: ''
  })

  useEffect(() => {
    loadEvents()
  }, [filters])

  const loadEvents = async () => {
    try {
      const params = new URLSearchParams()
      if (filters.severity) params.set('severity', filters.severity)
      if (filters.event_type) params.set('event_type', filters.event_type)
      if (filters.source_ip) params.set('source_ip', filters.source_ip)

      const response = await api.get(`/api/events?${params}`)
      setEvents(response.data.events || [])
    } catch (error) {
      console.error('Erro ao carregar eventos:', error)
    } finally {
      setLoading(false)
    }
  }

  const getSeverityBadge = (severity: string) => {
    const badges: Record<string, string> = {
      low: 'badge-low',
      medium: 'badge-medium',
      high: 'badge-high',
      critical: 'badge-critical'
    }
    return `badge ${badges[severity] || 'badge-low'}`
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return (
    <div>
      <div className="header">
        <h2>Eventos de Segurança</h2>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="card-header">
          <h3>Filtros</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
          <div className="form-group">
            <label>Severidade</label>
            <select value={filters.severity} onChange={(e) => setFilters({...filters, severity: e.target.value})}>
              <option value="">Todas</option>
              <option value="low">Baixa</option>
              <option value="medium">Média</option>
              <option value="high">Alta</option>
              <option value="critical">Crítica</option>
            </select>
          </div>

          <div className="form-group">
            <label>Tipo de Evento</label>
            <select value={filters.event_type} onChange={(e) => setFilters({...filters, event_type: e.target.value})}>
              <option value="">Todos</option>
              <option value="honeypot_login">Honeypot Login</option>
              <option value="honeypot_command">Honeypot Command</option>
              <option value="auth_failure">Auth Failure</option>
              <option value="suspicious_process">Suspicious Process</option>
            </select>
          </div>

          <div className="form-group">
            <label>IP de Origem</label>
            <input 
              type="text" 
              value={filters.source_ip}
              onChange={(e) => setFilters({...filters, source_ip: e.target.value})}
              placeholder="192.168.1.100"
            />
          </div>
        </div>
      </div>

      {/* Events Table */}
      <div className="card">
        <div className="card-header">
          <h3>Eventos ({events.length})</h3>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Tipo</th>
                <th>Severidade</th>
                <th>IP Origem</th>
                <th>Username</th>
                <th>MITRE Technique</th>
                <th>Fonte</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event: any) => (
                <tr key={event.id}>
                  <td>{new Date(event.timestamp).toLocaleString('pt-BR')}</td>
                  <td>{event.event_type}</td>
                  <td>
                    <span className={getSeverityBadge(event.severity)}>
                      {event.severity}
                    </span>
                  </td>
                  <td><code>{event.source_ip || 'N/A'}</code></td>
                  <td>{event.username || '-'}</td>
                  <td>{event.mitre_technique_id || '-'}</td>
                  <td>{event.source}</td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '20px' }}>
                    Nenhum evento encontrado
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
