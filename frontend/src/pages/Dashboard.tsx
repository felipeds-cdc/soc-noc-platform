import { useState, useEffect } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts'
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
    const interval = setInterval(loadData, 30000) // Atualiza a cada 30s
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

      setKpis(kpisRes.data)
      setTimeSeries(timeRes.data)
      setTopItems(topRes.data)
      setHoneypotSessions(honeypotRes.data.sessions || [])
    } catch (error) {
      console.error('Erro ao carregar dados:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return (
    <div>
      <div className="header">
        <h2>Dashboard</h2>
        <div className="header-actions">
          <span className="user-badge">Última atualização: {new Date().toLocaleTimeString('pt-BR')}</span>
        </div>
      </div>

      {/* KPIs */}
      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label">
            <FiActivity /> Total de Eventos (24h)
          </div>
          <div className="kpi-value">{kpis?.total_events_24h || 0}</div>
        </div>

        <div className="kpi-card critical">
          <div className="kpi-label">
            <FiAlertTriangle /> Alertas Críticos
          </div>
          <div className="kpi-value" style={{ color: 'var(--accent-red)' }}>
            {kpis?.critical_alerts || 0}
          </div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label">
            <FiShield /> Alertas Altos
          </div>
          <div className="kpi-value" style={{ color: 'var(--accent-yellow)' }}>
            {kpis?.high_alerts || 0}
          </div>
        </div>

        <div className="kpi-card success">
          <div className="kpi-label">
            <FiTerminal /> Sessões Honeypot
          </div>
          <div className="kpi-value" style={{ color: 'var(--accent-green)' }}>
            {kpis?.honeypot_sessions_24h || 0}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label">
            <FiGlobe /> IPs Únicos
          </div>
          <div className="kpi-value">{kpis?.unique_source_ips || 0}</div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label">
            <FiUsers /> Tentativas Brute Force
          </div>
          <div className="kpi-value">{kpis?.brute_force_attempts || 0}</div>
        </div>
      </div>

      {/* Charts */}
      <div className="grid-2">
        <div className="card">
          <div className="card-header">
            <h3>Timeline de Eventos</h3>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeries.events || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="timestamp" stroke="var(--text-secondary)" tick={{ fontSize: 12 }} />
                <YAxis stroke="var(--text-secondary)" />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}
                />
                <Line type="monotone" dataKey="count" stroke="var(--accent-blue)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Top Países de Origem</h3>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={topItems.top_countries || []}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ key, percent }) => `${key} ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="count"
                >
                  {(topItems.top_countries || []).map((_: any, index: number) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Top IPs de Origem</h3>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topItems.top_source_ips || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="key" stroke="var(--text-secondary)" tick={{ fontSize: 11 }} />
                <YAxis stroke="var(--text-secondary)" />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}
                />
                <Bar dataKey="count" fill="var(--accent-blue)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Tipos de Eventos</h3>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topItems.top_event_types || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="key" stroke="var(--text-secondary)" tick={{ fontSize: 11 }} />
                <YAxis stroke="var(--text-secondary)" />
                <Tooltip 
                  contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border-color)' }}
                />
                <Bar dataKey="count" fill="var(--accent-purple)" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Recent Honeypot Sessions */}
      <div className="card">
        <div className="card-header">
          <h3>Últimas Sessões do Honeypot</h3>
        </div>
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th>IP de Origem</th>
                <th>Username</th>
                <th>Password</th>
                <th>País</th>
                <th>Duração</th>
                <th>Início</th>
              </tr>
            </thead>
            <tbody>
              {honeypotSessions.slice(0, 10).map((session: any) => (
                <tr key={session.session_id}>
                  <td>{session.source_ip}</td>
                  <td><code>{session.username}</code></td>
                  <td><code>{session.password}</code></td>
                  <td>{session.geo_country || 'N/A'}</td>
                  <td>{session.session_duration || 0}s</td>
                  <td>{new Date(session.started_at).toLocaleString('pt-BR')}</td>
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
