import { useState, useEffect } from 'react'
import api from '../services/api'

export default function Alerts() {
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [filterStatus, setFilterStatus] = useState('')

  useEffect(() => {
    loadAlerts()
  }, [filterStatus])

  const loadAlerts = async () => {
    try {
      const params = filterStatus ? `?status=${filterStatus}` : ''
      const response = await api.get(`/api/alerts${params}`)
      setAlerts(response.data.alerts || [])
    } catch (error) {
      console.error('Erro ao carregar alertas:', error)
    } finally {
      setLoading(false)
    }
  }

  const updateAlertStatus = async (alertId: string, status: string) => {
    try {
      await api.patch(`/api/alerts/${alertId}`, { status })
      loadAlerts()
    } catch (error) {
      console.error('Erro ao atualizar alerta:', error)
    }
  }

  const getSeverityColor = (severity: string) => {
    const colors: Record<string, string> = {
      low: 'var(--accent-green)',
      medium: 'var(--accent-yellow)',
      high: 'var(--accent-red)',
      critical: '#ff6b6b'
    }
    return colors[severity] || 'var(--text-secondary)'
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return (
    <div>
      <div className="header">
        <h2>Alertas</h2>
        <div className="header-actions">
          <select 
            value={filterStatus} 
            onChange={(e) => setFilterStatus(e.target.value)}
            style={{ width: 'auto' }}
          >
            <option value="">Todos</option>
            <option value="triggered">Triggered</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
      </div>

      <div className="card">
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>Criado em</th>
                <th>Regra</th>
                <th>Severidade</th>
                <th>Status</th>
                <th>Descrição</th>
                <th>Ações</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert: any) => (
                <tr key={alert.id}>
                  <td>{new Date(alert.created_at).toLocaleString('pt-BR')}</td>
                  <td>
                    <strong>{alert.rule_name}</strong>
                    <br />
                    <small style={{ color: 'var(--text-secondary)' }}>{alert.rule_id}</small>
                  </td>
                  <td>
                    <span 
                      className="badge"
                      style={{ 
                        background: `${getSeverityColor(alert.severity)}20`,
                        color: getSeverityColor(alert.severity)
                      }}
                    >
                      {alert.severity}
                    </span>
                  </td>
                  <td>
                    <span className={`badge badge-${alert.status === 'triggered' ? 'critical' : 'low'}`}>
                      {alert.status}
                    </span>
                  </td>
                  <td>{alert.description || '-'}</td>
                  <td>
                    {alert.status === 'triggered' && (
                      <button 
                        className="btn btn-primary"
                        style={{ padding: '5px 10px', fontSize: '0.85rem' }}
                        onClick={() => updateAlertStatus(alert.id, 'acknowledged')}
                      >
                        Acknowledge
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {alerts.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '20px' }}>
                    Nenhum alerta encontrado
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
