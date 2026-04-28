import axios from 'axios'
import api, { apiPost, withTrailingSlash } from './api'
import { type AuthUser, clearAuthSession, setStoredUser, setToken } from './authStorage'

interface LoginResponse {
  access_token: string
  token_type?: string
  user_id?: string
  username?: string
  role?: string
}

function parseAuthUser(payload: LoginResponse): AuthUser {
  return {
    user_id: String(payload.user_id || ''),
    username: String(payload.username || 'user'),
    role: String(payload.role || 'viewer'),
  }
}

export async function loginRequest(username: string, password: string): Promise<AuthUser> {
  try {
    const loginData = await apiPost<LoginResponse, { username: string; password: string }>(
      '/api/auth/login',
      {
        username,
        password,
      },
    )

    if (!loginData?.access_token) {
      throw new Error('Resposta de autenticação inválida.')
    }

    const user = parseAuthUser(loginData)
    setToken(loginData.access_token)
    setStoredUser(user)

    return user
  } catch (error) {
    // Fallback for OAuth2-style endpoints expecting form-urlencoded payload.
    if (axios.isAxiosError(error) && [400, 415, 422].includes(error.response?.status ?? 0)) {
      const body = new URLSearchParams()
      body.set('username', username)
      body.set('password', password)

      const loginData = await apiPost<LoginResponse, URLSearchParams>(
        withTrailingSlash('/api/auth/login'),
        body,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        },
      )

      if (!loginData?.access_token) {
        throw new Error('Resposta de autenticação inválida.')
      }

      const user = parseAuthUser(loginData)
      setToken(loginData.access_token)
      setStoredUser(user)
      return user
    }

    throw error
  }
}

export async function meRequest(): Promise<AuthUser | null> {
  try {
    const profile = await api.get('/api/auth/me')
    if (!profile.data) {
      return null
    }

    const user = parseAuthUser(profile.data)
    setStoredUser(user)
    return user
  } catch {
    return null
  }
}

export function logoutRequest(): void {
  clearAuthSession()
}
