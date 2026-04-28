import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Toaster } from 'react-hot-toast'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Events from './pages/Events'
import Alerts from './pages/Alerts'
import Honeypot from './pages/Honeypot'
import ThreatHunting from './pages/ThreatHunting'
import Reports from './pages/Reports'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { LoadingProvider } from './contexts/LoadingContext'
import Layout from './components/Layout'
import ErrorBoundary from './components/ErrorBoundary'
import GlobalLoading from './components/GlobalLoading'

function PrivateRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return <div className="loading"><div className="spinner"></div></div>
  }

  return isAuthenticated ? <Navigate to="/dashboard" replace /> : <>{children}</>
}

function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />

      <Route
        path="/"
        element={
          <PrivateRoute>
            <Layout />
          </PrivateRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="events" element={<Events />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="honeypot" element={<Honeypot />} />
        <Route path="threat-hunting" element={<ThreatHunting />} />
        <Route path="reports" element={<Reports />} />
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <LoadingProvider>
          <AuthProvider>
            <Toaster position="top-right" />
            <GlobalLoading />
            <AppRoutes />
          </AuthProvider>
        </LoadingProvider>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
