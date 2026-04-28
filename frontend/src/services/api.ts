import axios, { AxiosError, AxiosHeaders, type AxiosRequestConfig, type InternalAxiosRequestConfig } from 'axios'
import { clearAuthSession, getToken } from './authStorage'

type RequestConfigWithRetry = InternalAxiosRequestConfig & { _retryCount?: number }

const DEFAULT_API_URL = 'http://localhost:8000'
const REQUEST_TIMEOUT_MS = 12000
const MAX_RETRIES = 1

function normalizeApiBaseUrl(url: string): string {
  return url.replace(/\/+$/, '')
}

const baseURL = normalizeApiBaseUrl(import.meta.env.VITE_API_URL || DEFAULT_API_URL)

let activeRequests = 0

function emitLoading(delta: number): void {
  if (typeof window === 'undefined') {
    return
  }

  activeRequests = Math.max(0, activeRequests + delta)
  window.dispatchEvent(
    new CustomEvent('api:loading', {
      detail: {
        active: activeRequests,
      },
    }),
  )
}

function notifyUnauthorized(): void {
  if (typeof window === 'undefined') {
    return
  }

  window.dispatchEvent(new CustomEvent('auth:unauthorized'))
}

function shouldRetry(error: AxiosError, config?: RequestConfigWithRetry): boolean {
  if (!config) {
    return false
  }

  if ((config._retryCount ?? 0) >= MAX_RETRIES) {
    return false
  }

  const method = (config.method || 'get').toLowerCase()
  const retryableMethod = method === 'get' || method === 'head' || method === 'options'
  if (!retryableMethod) {
    return false
  }

  if (!error.response) {
    return true
  }

  return error.response.status >= 500
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function ensureHeaders(config: InternalAxiosRequestConfig): AxiosHeaders {
  if (config.headers instanceof AxiosHeaders) {
    return config.headers
  }

  const headers = new AxiosHeaders(config.headers)
  config.headers = headers
  return headers
}

const api = axios.create({
  baseURL,
  timeout: REQUEST_TIMEOUT_MS,
  headers: {
    Accept: 'application/json',
  },
})

api.interceptors.request.use((config) => {
  emitLoading(1)

  const headers = ensureHeaders(config)
  const token = getToken()

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }

  const isFormData = typeof FormData !== 'undefined' && config.data instanceof FormData
  if (!isFormData && config.data && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  return config
})

api.interceptors.response.use(
  (response) => {
    emitLoading(-1)
    return response
  },
  async (error: AxiosError) => {
    emitLoading(-1)

    const config = error.config as RequestConfigWithRetry | undefined
    if (config && shouldRetry(error, config)) {
      config._retryCount = (config._retryCount ?? 0) + 1
      await wait(400 * config._retryCount)
      return api(config)
    }

    if (error.response?.status === 401) {
      clearAuthSession()
      notifyUnauthorized()
    }

    return Promise.reject(error)
  },
)

export function getApiBaseUrl(): string {
  return baseURL
}

export function withTrailingSlash(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`
  return normalized.endsWith('/') ? normalized : `${normalized}/`
}

export async function apiGet<T>(path: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await api.get<T>(path, config)
  return response.data
}

export async function apiPost<TResponse, TPayload>(
  path: string,
  payload?: TPayload,
  config?: AxiosRequestConfig,
): Promise<TResponse> {
  const response = await api.post<TResponse>(path, payload, config)
  return response.data
}

export async function apiPatch<TResponse, TPayload>(
  path: string,
  payload: TPayload,
  config?: AxiosRequestConfig,
): Promise<TResponse> {
  const response = await api.patch<TResponse>(path, payload, config)
  return response.data
}

export default api
