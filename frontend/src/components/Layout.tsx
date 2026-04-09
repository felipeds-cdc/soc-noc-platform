import { Outlet, Link, useLocation } from 'react-router-dom'
import { useAuth } from '../contexts/AuthContext'
import { 
  FiShield, FiActivity, FiAlertTriangle, FiTerminal, 
  FiSearch, FiFileText, FiLogOut 
} from 'react-icons/fi'

export default function Layout() {
  const { user, logout } = useAuth()
  const location = useLocation()

  const navItems = [
    { path: '/dashboard', icon: FiActivity, label: 'Dashboard' },
    { path: '/events', icon: FiShield, label: 'Eventos' },
    { path: '/alerts', icon: FiAlertTriangle, label: 'Alertas' },
    { path: '/honeypot', icon: FiTerminal, label: 'Honeypot' },
    { path: '/threat-hunting', icon: FiSearch, label: 'Threat Hunting' },
    { path: '/reports', icon: FiFileText, label: 'Relatórios' },
  ]

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
            <Link
              key={item.path}
              to={item.path}
              className={location.pathname === item.path ? 'active' : ''}
            >
              <item.icon />
              {item.label}
            </Link>
          ))}
        </nav>
        
        <div style={{ padding: '20px', borderTop: '1px solid var(--border-color)' }}>
          <div className="user-badge">
            👤 {user?.username} ({user?.role})
          </div>
          <button className="btn btn-secondary" style={{ width: '100%', marginTop: '10px' }} onClick={logout}>
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
