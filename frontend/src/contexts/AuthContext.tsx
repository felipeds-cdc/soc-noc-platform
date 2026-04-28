import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { loginRequest, logoutRequest, meRequest } from '../services/authService'
import { getStoredUser, getToken, type AuthUser } from '../services/authStorage'

interface AuthContextType {
  user: AuthUser | null
  login: (username: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
  isAuthenticated: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true

    const bootstrapAuth = async () => {
      try {
        const token = getToken()
        const storedUser = getStoredUser()

        if (!token) {
          if (mounted) setUser(null)
          return
        }

        if (storedUser && mounted) {
          setUser(storedUser)
        }

        const refreshedUser = await meRequest()
        if (mounted && refreshedUser) {
          setUser(refreshedUser)
        }
      } finally {
        if (mounted) {
          setLoading(false)
        }
      }
    }

    bootstrapAuth()

    const unauthorizedListener = () => {
      if (mounted) {
        setUser(null)
      }
    }

    window.addEventListener('auth:unauthorized', unauthorizedListener)

    return () => {
      mounted = false
      window.removeEventListener('auth:unauthorized', unauthorizedListener)
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const authUser = await loginRequest(username, password)
    setUser(authUser)
  }, [])

  const logout = useCallback(() => {
    logoutRequest()
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({
      user,
      login,
      logout,
      loading,
      isAuthenticated: Boolean(user),
    }),
    [login, loading, logout, user],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider')
  }
  return context
}
