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
      setSessions(sessionsRes.data.sessions || [])
      setCredentials(credsRes.data || [])
    } catch (error) {
      console.error('Erro ao carregar dados do honeypot:', error)
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
        <h2>Honeypot SSH</h2>
      </div>

      {/* Tabs */}
      <div className="card">
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
                  <tr key={session.session_id}>
                    <td><code style={{ fontSize: '0.85rem' }}>{session.session_id.substring(0, 8)}...</code></td>
                    <td><code>{session.source_ip}</code></td>
                    <td><code>{session.username}</code></td>
                    <td><code>{session.password}</code></td>
                    <td>{session.geo_country || 'N/A'}</td>
                    <td>{session.commands_executed?.length || 0}</td>
                    <td>{session.session_duration || 0}s</td>
                    <td>{new Date(session.started_at).toLocaleString('pt-BR')}</td>
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
                {credentials.map((cred: any, idx: number) => (
                  <tr key={idx}>
                    <td><code>{cred.username}</code></td>
                    <td><code>{cred.password}</code></td>
                    <td>{cred.count}</td>
                    <td>{cred.source_ips.join(', ')}</td>
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
