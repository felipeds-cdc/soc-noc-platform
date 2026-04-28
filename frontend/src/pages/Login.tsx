import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { FiShield } from 'react-icons/fi'
import { useAuth } from '../contexts/AuthContext'
import { useApiRequest } from '../hooks/useApiRequest'
import { getErrorMessage } from '../services/error'

export default function Login() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const { login } = useAuth()
  const navigate = useNavigate()
  const { loading, run } = useApiRequest()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    const safeUsername = username.trim()
    const safePassword = password.trim()

    if (!safeUsername || !safePassword) {
      toast.error('Usuário e senha são obrigatórios.')
      return
    }

    try {
      await run(() => login(safeUsername, safePassword), { silent: true })
      toast.success('Login realizado com sucesso!')
      navigate('/dashboard', { replace: true })
    } catch (error) {
      toast.error(getErrorMessage(error, 'Não foi possível autenticar.'))
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>
          <FiShield style={{ verticalAlign: 'middle' }} /> SOC/NOC Platform
        </h2>

        <div className="warning">
          ⚠️ <strong>AVISO:</strong> Sistema destinado exclusivamente a ambientes laboratoriais e autorizados.
        </div>

        <form onSubmit={handleSubmit} noValidate>
          <div className="form-group">
            <label htmlFor="username">Usuário</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Senha</label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••"
              autoComplete="current-password"
              required
            />
          </div>

          <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
            {loading ? 'Entrando...' : 'Entrar'}
          </button>
        </form>

        <p style={{ marginTop: '20px', fontSize: '0.85rem', color: 'var(--text-secondary)', textAlign: 'center' }}>
          Entre em contato com o administrador para obter credenciais de acesso.
        </p>
      </div>
    </div>
  )
}
