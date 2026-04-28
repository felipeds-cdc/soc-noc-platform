import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import { ErrorState } from '../components/PageState'
import { getErrorMessage } from '../services/error'
import { fetchEvents, type EventsFilters, type SecurityEvent } from '../services/eventsService'

export default function Events() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filters, setFilters] = useState<EventsFilters>({
    severity: '',
    event_type: '',
    source_ip: '',
  })

  useEffect(() => {
    let mounted = true

    const load = async () => {
      try {
        if (mounted) {
          setError(null)
        }

        const eventData = await fetchEvents(filters)
        if (!mounted) {
          return
        }

        setEvents(eventData)
      } catch (requestError) {
        if (!mounted) {
          return
        }

        const message = getErrorMessage(requestError, 'Não foi possível carregar os eventos.')
        setError(message)
        toast.error(message)
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    load()
    return () => {
      mounted = false
    }
  }, [filters])

  const getSeverityBadge = (severity: string) => {
    const badges: Record<string, string> = {
      low: 'badge-low',
      medium: 'badge-medium',
      high: 'badge-high',
      critical: 'badge-critical',
    }

    return `badge ${badges[severity] || 'badge-low'}`
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  if (error) {
    return (
      <ErrorState
        title="Falha ao carregar eventos"
        message={error}
        action={{
          label: 'Recarregar',
          onClick: () => {
            setLoading(true)
            setFilters((previous) => ({ ...previous }))
          },
        }}
      />
    )
  }

  return (
    <div>
      <div className="header">
        <h2>Eventos de Segurança</h2>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>Filtros</h3>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '15px' }}>
          <div className="form-group">
            <label htmlFor="severity">Severidade</label>
            <select id="severity" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
              <option value="">Todas</option>
              <option value="low">Baixa</option>
              <option value="medium">Média</option>
              <option value="high">Alta</option>
              <option value="critical">Crítica</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="event-type">Tipo de Evento</label>
            <select
              id="event-type"
              value={filters.event_type}
              onChange={(e) => setFilters({ ...filters, event_type: e.target.value })}
            >
              <option value="">Todos</option>
              <option value="honeypot_login">Honeypot Login</option>
              <option value="honeypot_command">Honeypot Command</option>
              <option value="auth_failure">Auth Failure</option>
              <option value="suspicious_process">Suspicious Process</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="source-ip">IP de Origem</label>
            <input
              id="source-ip"
              type="text"
              value={filters.source_ip}
              onChange={(e) => setFilters({ ...filters, source_ip: e.target.value })}
              placeholder="192.168.1.100"
            />
          </div>
        </div>
      </div>

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
              {events.map((event, index) => (
                <tr key={event.id || `${event.timestamp || 'unknown'}-${index}`}>
                  <td>{event.timestamp ? new Date(event.timestamp).toLocaleString('pt-BR') : 'N/A'}</td>
                  <td>{event.event_type || 'N/A'}</td>
                  <td>
                    <span className={getSeverityBadge(event.severity || 'low')}>
                      {event.severity || 'low'}
                    </span>
                  </td>
                  <td><code>{event.source_ip || 'N/A'}</code></td>
                  <td>{event.username || '-'}</td>
                  <td>{event.mitre_technique_id || '-'}</td>
                  <td>{event.source || 'N/A'}</td>
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
