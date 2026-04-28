export interface AuthUser {
  user_id: string
  username: string
  role: string
}

const TOKEN_KEY = 'token'
const USER_KEY = 'user'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function getStoredUser(): AuthUser | null {
  const rawUser = localStorage.getItem(USER_KEY)
  if (!rawUser) {
    return null
  }

  try {
    const parsed = JSON.parse(rawUser)
    if (parsed && typeof parsed.username === 'string') {
      return parsed as AuthUser
    }
  } catch {
    localStorage.removeItem(USER_KEY)
  }

  return null
}

export function setStoredUser(user: AuthUser): void {
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearStoredUser(): void {
  localStorage.removeItem(USER_KEY)
}

export function clearAuthSession(): void {
  clearToken()
  clearStoredUser()
}
