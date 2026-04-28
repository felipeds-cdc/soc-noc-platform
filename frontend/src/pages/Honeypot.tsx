import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import { ErrorState } from '../components/PageState'
import {
  fetchHoneypotCredentials,
  fetchHoneypotSessions,
  type HoneypotSession,
} from '../services/dashboardService'
import { getErrorMessage } from '../services/error'

function getField(session: HoneypotSession, field: 'source_ip' | 'username' | 'password') {
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

export default function Honeypot() {
  const [sessions, setSessions] = useState<HoneypotSession[]>([])
  const [credentials, setCredentials] = useState<Array<{ username: string; password: string; count: number; source_ips: string[] }>>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'sessions' | 'credentials'>('sessions')

  useEffect(() => {
    let mounted = true

    const load = async () => {
      try {
        if (mounted) {
          setError(null)
        }

        const [sessionsData, credentialsData] = await Promise.all([
          fetchHoneypotSessions(),
          fetchHoneypotCredentials(),
        ])

        if (!mounted) {
          return
        }

        setSessions(sessionsData)
        setCredentials(credentialsData)
      } catch (requestError) {
        if (!mounted) {
          return
        }

        const message = getErrorMessage(requestError, 'Não foi possível carregar dados do honeypot.')
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
  }, [])

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  if (error) {
    return (
      <ErrorState
        title="Falha ao carregar honeypot"
        message={error}
        action={{
          label: 'Recarregar',
          onClick: () => window.location.reload(),
        }}
      />
    )
  }

  return (
    <div>
      <div className="header">
        <h2>Honeypot SSH</h2>
      </div>

      <div className="card">
        <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
          <button className={`btn ${activeTab === 'sessions' ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setActiveTab('sessions')}>
            Sessões
          </button>

          <button
            className={`btn ${activeTab === 'credentials' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('credentials')}
          >
            Credenciais Capturadas
          </button>
        </div>

        {activeTab === 'sessions' && (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Session ID</th>
                  <th>IP de Origem</th>
                  <th>Username</th>
                  <th>Password</th>
                  <th>País</th>
                  <th>Comandos</th>
                  <th>Duração</th>
                  <th>Início</th>
                </tr>
              </thead>
              <tbody>
                {sessions.map((session, index) => (
                  <tr key={session.session_id || `${session.started_at || 'unknown'}-${index}`}>
                    <td>
                      <code style={{ fontSize: '0.85rem' }}>
                        {session.session_id ? `${session.session_id.substring(0, 8)}...` : 'N/A'}
                      </code>
                    </td>

                    <td><code>{String(getField(session, 'source_ip') || 'N/A')}</code></td>
                    <td><code>{String(getField(session, 'username') || 'N/A')}</code></td>
                    <td><code>{String(getField(session, 'password') || 'N/A')}</code></td>
                    <td>{session.geo_country || 'N/A'}</td>
                    <td>{Array.isArray((session as any).commands_executed) ? (session as any).commands_executed.length : 0}</td>
                    <td>{session.session_duration ? `${session.session_duration}s` : '0s'}</td>
                    <td>{session.started_at ? new Date(session.started_at).toLocaleString('pt-BR') : 'N/A'}</td>
                  </tr>
                ))}

                {sessions.length === 0 && (
                  <tr>
                    <td colSpan={8} style={{ textAlign: 'center', padding: '20px' }}>
                      Nenhuma sessão registrada ainda
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'credentials' && (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Password</th>
                  <th>Tentativas</th>
                  <th>IP(s) de Origem</th>
                </tr>
              </thead>
              <tbody>
                {credentials.map((credential, index) => (
                  <tr key={`${credential.username}-${credential.password}-${index}`}>
                    <td><code>{credential.username || 'N/A'}</code></td>
                    <td><code>{credential.password || 'N/A'}</code></td>
                    <td>{credential.count}</td>
                    <td>{credential.source_ips.join(', ') || 'N/A'}</td>
                  </tr>
                ))}

                {credentials.length === 0 && (
                  <tr>
                    <td colSpan={4} style={{ textAlign: 'center', padding: '20px' }}>
                      Nenhuma credencial capturada ainda
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
