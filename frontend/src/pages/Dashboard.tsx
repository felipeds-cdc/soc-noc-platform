import { useEffect, useState } from 'react'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
} from 'recharts'
import { FiActivity, FiAlertTriangle, FiShield, FiTerminal, FiGlobe, FiUsers } from 'react-icons/fi'
import toast from 'react-hot-toast'
import {
  fetchDashboardKpis,
  fetchDashboardTimeSeries,
  fetchDashboardTopItems,
  fetchHoneypotSessions,
  type DashboardKpis,
  type DashboardTimeSeries,
  type DashboardTopItems,
  type HoneypotSession,
} from '../services/dashboardService'
import { getErrorMessage } from '../services/error'
import { ErrorState } from '../components/PageState'

const COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']

const INITIAL_KPIS: DashboardKpis = {
  total_events_24h: 0,
  critical_alerts: 0,
  high_alerts: 0,
  honeypot_sessions_24h: 0,
  unique_source_ips: 0,
  brute_force_attempts: 0,
}

const INITIAL_TIME_SERIES: DashboardTimeSeries = {
  events: [],
  alerts: [],
}

const INITIAL_TOP_ITEMS: DashboardTopItems = {
  top_countries: [],
  top_source_ips: [],
}

function getSessionField(session: HoneypotSession, field: 'source_ip' | 'username' | 'password') {
  if (session?.[field]) {
    return session[field]
  }

  if (session?.data && typeof session.data === 'string') {
    try {
      const parsed = JSON.parse(session.data)
      return parsed?.[field]
    } catch {
      return undefined
    }
  }

  if (session?.data && typeof session.data === 'object') {
    return (session.data as Record<string, unknown>)?.[field]
  }

  return undefined
}

export default function Dashboard() {
  const [kpis, setKpis] = useState<DashboardKpis>(INITIAL_KPIS)
  const [timeSeries, setTimeSeries] = useState<DashboardTimeSeries>(INITIAL_TIME_SERIES)
  const [topItems, setTopItems] = useState<DashboardTopItems>(INITIAL_TOP_ITEMS)
  const [honeypotSessions, setHoneypotSessions] = useState<HoneypotSession[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true

    const run = async () => {
      await loadData(mounted)
    }

    run()
    const interval = window.setInterval(run, 30000)

    return () => {
      mounted = false
      window.clearInterval(interval)
    }
  }, [])

  const loadData = async (mounted = true) => {
    try {
      if (mounted) {
        setError(null)
      }

      const [kpisData, timeSeriesData, topItemsData, sessionsData] = await Promise.all([
        fetchDashboardKpis(),
        fetchDashboardTimeSeries(),
        fetchDashboardTopItems(),
        fetchHoneypotSessions(),
      ])

      if (!mounted) {
        return
      }

      setKpis(kpisData)
      setTimeSeries(timeSeriesData)
      setTopItems(topItemsData)
      setHoneypotSessions(sessionsData)
    } catch (requestError) {
      if (!mounted) {
        return
      }

      const message = getErrorMessage(requestError, 'Não foi possível carregar o dashboard.')
      setError(message)
      toast.error(message)
    } finally {
      if (mounted) {
        setLoading(false)
      }
    }
  }

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  if (error) {
    return (
      <ErrorState
        title="Falha ao carregar dashboard"
        message={error}
        action={{ label: 'Tentar novamente', onClick: () => loadData(true) }}
      />
    )
  }

  return (
    <div>
      <div className="header">
        <h2>Dashboard</h2>
        <div className="header-actions">
          <span className="user-badge">Última atualização: {new Date().toLocaleTimeString('pt-BR')}</span>
        </div>
      </div>

      <div className="kpi-grid">
        <div className="kpi-card">
          <div className="kpi-label"><FiActivity /> Total de Eventos (24h)</div>
          <div className="kpi-value">{kpis.total_events_24h}</div>
        </div>

        <div className="kpi-card critical">
          <div className="kpi-label"><FiAlertTriangle /> Alertas Críticos</div>
          <div className="kpi-value" style={{ color: 'var(--accent-red)' }}>{kpis.critical_alerts}</div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label"><FiShield /> Alertas Altos</div>
          <div className="kpi-value" style={{ color: 'var(--accent-yellow)' }}>{kpis.high_alerts}</div>
        </div>

        <div className="kpi-card success">
          <div className="kpi-label"><FiTerminal /> Sessões Honeypot</div>
          <div className="kpi-value" style={{ color: 'var(--accent-green)' }}>
            {kpis.honeypot_sessions_24h || honeypotSessions.length}
          </div>
        </div>

        <div className="kpi-card">
          <div className="kpi-label"><FiGlobe /> IPs Únicos</div>
          <div className="kpi-value">{kpis.unique_source_ips}</div>
        </div>

        <div className="kpi-card warning">
          <div className="kpi-label"><FiUsers /> Tentativas Brute Force</div>
          <div className="kpi-value">{kpis.brute_force_attempts}</div>
        </div>
      </div>

      <div className="grid-2">
        <div className="card">
          <div className="card-header"><h3>Timeline de Eventos</h3></div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={timeSeries.events}>
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
                <Pie
                  data={topItems.top_countries}
                  dataKey="count"
                  nameKey="label"
                  cx="50%"
                  cy="50%"
                  outerRadius={80}
                >
                  {topItems.top_countries.map((country, index) => (
                    <Cell key={`${country.label || country.key || 'country'}-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

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
              {honeypotSessions.slice(0, 10).map((session, index) => (
                <tr key={session.session_id || `${session.started_at || 'unknown'}-${index}`}>
                  <td>{String(getSessionField(session, 'source_ip') || 'N/A')}</td>
                  <td><code>{String(getSessionField(session, 'username') || 'N/A')}</code></td>
                  <td><code>{String(getSessionField(session, 'password') || 'N/A')}</code></td>
                  <td>{session.geo_country || 'N/A'}</td>
                  <td>{session.session_duration ? `${session.session_duration}s` : '0s'}</td>
                  <td>{session.started_at ? new Date(session.started_at).toLocaleString('pt-BR') : 'N/A'}</td>
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
