import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import MockAdapter from 'axios-mock-adapter'
import api, { apiGet } from '../api'
import { fetchDashboardKpis, fetchDashboardTimeSeries, fetchDashboardTopItems } from '../dashboardService'
import { loginRequest } from '../authService'
import { clearAuthSession, getToken } from '../authStorage'
import { getErrorMessage } from '../error'

type Listener = (event: Event) => void

class MemoryStorage {
  private store = new Map<string, string>()

  getItem(key: string): string | null {
    return this.store.has(key) ? this.store.get(key)! : null
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value)
  }

  removeItem(key: string): void {
    this.store.delete(key)
  }

  clear(): void {
    this.store.clear()
  }
}

class EventEmitterWindow {
  private listeners = new Map<string, Set<Listener>>()

  addEventListener(type: string, listener: Listener): void {
    if (!this.listeners.has(type)) {
      this.listeners.set(type, new Set())
    }
    this.listeners.get(type)?.add(listener)
  }

  removeEventListener(type: string, listener: Listener): void {
    this.listeners.get(type)?.delete(listener)
  }

  dispatchEvent(event: Event): boolean {
    this.listeners.get(event.type)?.forEach((listener) => listener(event))
    return true
  }
}

class MockCustomEvent<T = unknown> extends Event {
  detail?: T

  constructor(type: string, init?: CustomEventInit<T>) {
    super(type)
    this.detail = init?.detail
  }
}

const memoryStorage = new MemoryStorage()
const mockWindow = new EventEmitterWindow()

vi.stubGlobal('localStorage', memoryStorage)
vi.stubGlobal('window', mockWindow)
vi.stubGlobal('CustomEvent', MockCustomEvent)

describe('Frontend audit scenarios', () => {
  let mock: MockAdapter

  beforeEach(() => {
    mock = new MockAdapter(api)
    clearAuthSession()
  })

  afterEach(() => {
    mock.restore()
    clearAuthSession()
    memoryStorage.clear()
  })

  it('simula login com sucesso', async () => {
    mock.onPost('/api/auth/login').reply(200, {
      access_token: 'jwt-success',
      user_id: '1',
      username: 'admin',
      role: 'admin',
    })

    const user = await loginRequest('admin', 'secret')

    expect(user.username).toBe('admin')
    expect(getToken()).toBe('jwt-success')
  })

  it('simula login inválido (401)', async () => {
    mock.onPost('/api/auth/login').reply(401, { detail: 'Credenciais inválidas' })

    await expect(loginRequest('admin', 'bad-pass')).rejects.toBeTruthy()
    expect(getToken()).toBeNull()
  })

  it('simula token expirado (401) e limpa sessão automaticamente', async () => {
    localStorage.setItem('token', 'expired-token')
    localStorage.setItem('user', JSON.stringify({ username: 'admin', role: 'admin', user_id: '1' }))

    const unauthorizedSpy = vi.fn()
    window.addEventListener('auth:unauthorized', unauthorizedSpy)

    mock.onGet('/api/events').reply(401, { detail: 'Token expirado' })

    await expect(apiGet('/api/events')).rejects.toBeTruthy()

    expect(getToken()).toBeNull()
    expect(localStorage.getItem('user')).toBeNull()
    expect(unauthorizedSpy).toHaveBeenCalledTimes(1)
  })

  it('simula API offline e valida mensagem de rede', async () => {
    mock.onGet('/api/events').networkError()

    try {
      await apiGet('/api/events')
      throw new Error('Expected request to fail')
    } catch (error) {
      const message = getErrorMessage(error)
      expect(message.toLowerCase()).toContain('rede')
    }
  })

  it('simula respostas vazias no dashboard sem quebrar formato', async () => {
    mock.onGet('/api/dashboard/kpis/').reply(200, null)
    mock.onGet('/api/dashboard/time-series/').reply(200, {})
    mock.onGet('/api/dashboard/top-items/').reply(200, { top_countries: [] })

    const [kpis, timeSeries, topItems] = await Promise.all([
      fetchDashboardKpis(),
      fetchDashboardTimeSeries(),
      fetchDashboardTopItems(),
    ])

    expect(kpis.total_events_24h).toBe(0)
    expect(Array.isArray(timeSeries.events)).toBe(true)
    expect(Array.isArray(topItems.top_countries)).toBe(true)
  })

  it('simula erro 500 com retry automático em GET', async () => {
    let count = 0

    mock.onGet('/api/dashboard/kpis/').reply(() => {
      count += 1
      if (count === 1) {
        return [500, { detail: 'erro interno' }]
      }

      return [200, { total_events_24h: 7 }]
    })

    const kpis = await fetchDashboardKpis()

    expect(count).toBe(2)
    expect(kpis.total_events_24h).toBe(7)
  })
})
