import { useState, useEffect } from 'react'
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell
} from 'recharts'
import { FiActivity, FiAlertTriangle, FiShield, FiTerminal, FiGlobe, FiUsers } from 'react-icons/fi'
import api from '../services/api'

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']

export default function Dashboard() {
  const [kpis, setKpis] = useState<any>(null)
  const [timeSeries, setTimeSeries] = useState<any>({ events: [], alerts: [] })
  const [topItems, setTopItems] = useState<any>({})
  const [honeypotSessions, setHoneypotSessions] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 30000)
    return () => clearInterval(interval)
  }, [])

  const loadData = async () => {
    try {
      const [kpisRes, timeRes, topRes, honeypotRes] = await Promise.all([
        api.get('/api/dashboard/kpis'),
        api.get('/api/dashboard/time-series'),
        api.get('/api/dashboard/top-items'),
        api.get('/api/dashboard/honeypot/sessions'),
      ])

      console.log("HONEYPOT RAW:", honeypotRes.data)

      // 🔥 Trata Elasticsearch ou API padrão
      const rawSessions = honeypotRes.data.sessions || honeypotRes.data || []

      const parsedSessions = rawSessions.map((s: any) => s._source || s)

      setKpis(kpisRes.data || {})
      setTimeSeries(timeRes.data || { events: [], alerts: [] })
      setTopItems(topRes.data || {})
      setHoneypotSessions(parsedSessions)

    } catch (error) {
      console.error('Erro ao carregar dados:', error)
    } finally {
      setLoading(false)
    }
  }

  // 🔥 Função segura para acessar campos (fallback em data JSON)
  const getField = (obj: any, field: string) => {
    if (obj?.[field]) return obj[field]

    if (obj?.data) {
      try {
        const parsed = typeof obj.data === 'string'
          ? JSON.parse(obj.data)
          : obj.data
        return parsed?.[field]
      } catch {
        return undefined
      }
    }

    return undefined
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return (
    <div>
      <div className="header">
        <h2>Dashboard</h2>
        <div className="header-actions">
          <span className="user-badge">
            Última atualização: {new Date().toLocaleTimeString('pt-BR')}
          </span>
        </div>
      </div>

      {/* KPIs */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label"><FiActivity /> Total de Eventos (24h)</div>
          <div className="kpi-value">{kpis?.total_events_24h || 0}</div>
        </div>

        <div className="kpi-card critical">
          <div className="kpi-label"><FiAlertTriangle /> Alertas Críticos</div>
          <div className="kpi-value" style={{ color: 'var(--accent-red)' }}>
            {kpis?.critical_alerts || 0}
          </div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label"><FiShield /> Alertas Altos</div>
          <div className="kpi-value" style={{ color: 'var(--accent-yellow)' }}>
            {kpis?.high_alerts || 0}
          </div>
        </div>

        <div className="kpi-card success">
          <div className="kpi-label"><FiTerminal /> Sessões Honeypot</div>
          <div className="kpi-value" style={{ color: 'var(--accent-green)' }}>
            {kpis?.honeypot_sessions_24h || honeypotSessions.length}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label"><FiGlobe /> IPs Únicos</div>
          <div className="kpi-value">{kpis?.unique_source_ips || 0}</div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label"><FiUsers /> Tentativas Brute Force</div>
          <div className="kpi-value">{kpis?.brute_force_attempts || 0}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h3>Timeline de Eventos</h3></div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeries.events || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="timestamp" />
                <YAxis />
                <Tooltip />
                <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header"><h3>Top Países</h3></div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={topItems.top_countries || []} dataKey="count" cx="50%" cy="50%" outerRadius={80}>
                  {(topItems.top_countries || []).map((_: any, i: number) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Honeypot Table */}
      <div className="card">
        <div className="card-header">
          <h3>Últimas Sessões do Honeypot</h3>
        </div>

        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>IP</th>
                <th>User</th>
                <th>Password</th>
                <th>País</th>
                <th>Duração</th>
                <th>Início</th>
              </tr>
            </thead>

            <tbody>
              {honeypotSessions.slice(0, 10).map((s: any, i: number) => (
                <tr key={s.session_id || i}>
                  <td>{getField(s, 'source_ip') || 'N/A'}</td>
                  <td><code>{getField(s, 'username') || 'N/A'}</code></td>
                  <td><code>{getField(s, 'password') || 'N/A'}</code></td>
                  <td>{s.geo_country || 'N/A'}</td>
                  <td>{s.session_duration ? `${s.session_duration}s` : '0s'}</td>
                  <td>
                    {s.started_at
                      ? new Date(s.started_at).toLocaleString('pt-BR')
                      : 'N/A'}
                  </td>
                </tr>
              ))}

              {honeypotSessions.length === 0 && (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '20px' }}>
                    Nenhuma sessão registrada ainda
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