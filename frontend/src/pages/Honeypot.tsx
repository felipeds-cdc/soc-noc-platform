import { useState, useEffect } from 'react'
import api from '../services/api'

export default function Honeypot() {
  const [sessions, setSessions] = useState<any[]>([])
  const [credentials, setCredentials] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'sessions' | 'credentials'>('sessions')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [sessionsRes, credsRes] = await Promise.all([
        api.get('/api/dashboard/honeypot/sessions'),
        api.get('/api/dashboard/honeypot/credentials'),
      ])

      console.log("RAW SESSIONS:", sessionsRes.data)

      // 🔥 Trata diferentes formatos de resposta (API ou Elasticsearch)
      const rawSessions = sessionsRes.data.sessions || sessionsRes.data || []

      const parsedSessions = rawSessions.map((s: any) => s._source || s)

      setSessions(parsedSessions)
      setCredentials(credsRes.data || [])

    } catch (error) {
      console.error('Erro ao carregar dados do honeypot:', error)
    } finally {
      setLoading(false)
    }
  }

  // 🔥 Função segura para acessar campos (inclusive dentro de "data")
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
        <h2>Honeypot SSH</h2>
      </div>

      <div className="card">
        {/* Tabs */}
        <div style={{ display: 'flex', gap: '10px', marginBottom: '20px' }}>
          <button 
            className={`btn ${activeTab === 'sessions' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('sessions')}
          >
            Sessões
          </button>

          <button 
            className={`btn ${activeTab === 'credentials' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setActiveTab('credentials')}
          >
            Credenciais Capturadas
          </button>
        </div>

        {/* SESSIONS */}
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
                {sessions.map((session: any) => (
                  <tr key={session.session_id || Math.random()}>
                    <td>
                      <code style={{ fontSize: '0.85rem' }}>
                        {session.session_id 
                          ? session.session_id.substring(0, 8) + '...' 
                          : 'N/A'}
                      </code>
                    </td>

                    <td>
                      <code>{getField(session, 'source_ip') || 'N/A'}</code>
                    </td>

                    <td>
                      <code>{getField(session, 'username') || 'N/A'}</code>
                    </td>

                    <td>
                      <code>{getField(session, 'password') || 'N/A'}</code>
                    </td>

                    <td>{session.geo_country || 'N/A'}</td>

                    <td>
                      {session.commands_executed?.length || 0}
                    </td>

                    <td>
                      {session.session_duration 
                        ? `${session.session_duration}s` 
                        : '0s'}
                    </td>

                    <td>
                      {session.started_at 
                        ? new Date(session.started_at).toLocaleString('pt-BR')
                        : 'N/A'}
                    </td>
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

        {/* CREDENTIALS */}
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
                {credentials.map((cred: any, idx: number) => (
                  <tr key={idx}>
                    <td><code>{cred.username}</code></td>
                    <td><code>{cred.password}</code></td>
                    <td>{cred.count}</td>
                    <td>{cred.source_ips?.join(', ') || 'N/A'}</td>
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
