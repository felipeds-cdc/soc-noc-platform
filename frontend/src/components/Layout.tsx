import { Outlet, Link, useLocation, useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { useAuth } from '../contexts/AuthContext'
import { FiShield, FiActivity, FiAlertTriangle, FiTerminal, FiSearch, FiFileText, FiLogOut } from 'react-icons/fi'

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()

  const navItems = [
    { path: '/dashboard', icon: FiActivity, label: 'Dashboard' },
    { path: '/events', icon: FiShield, label: 'Eventos' },
    { path: '/alerts', icon: FiAlertTriangle, label: 'Alertas' },
    { path: '/honeypot', icon: FiTerminal, label: 'Honeypot' },
    { path: '/threat-hunting', icon: FiSearch, label: 'Threat Hunting' },
    { path: '/reports', icon: FiFileText, label: 'Relatórios' },
  ]

  const handleLogout = () => {
    logout()
    toast.success('Sessão encerrada.')
    navigate('/login', { replace: true })
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h1>
            <FiShield /> SOC/NOC
          </h1>
          <p>Security Operations Center</p>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((item) => (
            <Link key={item.path} to={item.path} className={location.pathname === item.path ? 'active' : ''}>
              <item.icon />
              {item.label}
            </Link>
          ))}
        </nav>

        <div style={{ padding: '20px', borderTop: '1px solid var(--border-color)' }}>
          <div className="user-badge">
            👤 {user?.username || 'Usuário'} ({user?.role || 'sem perfil'})
          </div>
          <button className="btn btn-secondary" style={{ width: '100%', marginTop: '10px' }} onClick={handleLogout}>
            <FiLogOut /> Sair
          </button>
        </div>
      </aside>

      <main className="main-content">
        <Outlet />
      </main>
    </div>
  )
}
