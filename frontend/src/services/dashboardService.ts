import { apiGet, withTrailingSlash } from './api'

export interface DashboardKpis {
  total_events_24h: number
  critical_alerts: number
  high_alerts: number
  honeypot_sessions_24h: number
  unique_source_ips: number
  brute_force_attempts: number
}

export interface TimeSeriesPoint {
  timestamp: string
  count: number
}

export interface DashboardTimeSeries {
  events: TimeSeriesPoint[]
  alerts: TimeSeriesPoint[]
}

export interface TopItem {
  label?: string
  key?: string
  count: number
}

export interface DashboardTopItems {
  top_countries: TopItem[]
  top_source_ips: TopItem[]
}

export interface HoneypotSession {
  session_id?: string
  source_ip?: string
  username?: string
  password?: string
  geo_country?: string
  session_duration?: number
  started_at?: string
  data?: unknown
  _source?: HoneypotSession
}

function toNumber(value: unknown): number {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : 0
}

function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

function parseSession(session: HoneypotSession): HoneypotSession {
  return session?._source && typeof session._source === 'object'
    ? {
        ...session._source,
      }
    : session
}

function normalizeTopItems(raw: unknown): TopItem[] {
  return toArray<any>(raw)
    .map((item) => ({
      label: typeof item?.label === 'string' ? item.label : item?.country,
      key: typeof item?.key === 'string' ? item.key : undefined,
      count: toNumber(item?.count),
    }))
    .filter((item) => item.count > 0)
}

export async function fetchDashboardKpis(): Promise<DashboardKpis> {
  const data = await apiGet<any>(withTrailingSlash('/api/dashboard/kpis'))

  return {
    total_events_24h: toNumber(data?.total_events_24h),
    critical_alerts: toNumber(data?.critical_alerts),
    high_alerts: toNumber(data?.high_alerts),
    honeypot_sessions_24h: toNumber(data?.honeypot_sessions_24h),
    unique_source_ips: toNumber(data?.unique_source_ips),
    brute_force_attempts: toNumber(data?.brute_force_attempts),
  }
}

export async function fetchDashboardTimeSeries(): Promise<DashboardTimeSeries> {
  const data = await apiGet<any>(withTrailingSlash('/api/dashboard/time-series'))

  const mapPoint = (point: unknown): TimeSeriesPoint => ({
    timestamp: String((point as Record<string, unknown>)?.timestamp || (point as Record<string, unknown>)?.date || ''),
    count: toNumber((point as Record<string, unknown>)?.count),
  })

  return {
    events: toArray<any>(data?.events).map(mapPoint),
    alerts: toArray<any>(data?.alerts).map(mapPoint),
  }
}

export async function fetchDashboardTopItems(): Promise<DashboardTopItems> {
  const data = await apiGet<any>(withTrailingSlash('/api/dashboard/top-items'))

  return {
    top_countries: normalizeTopItems(data?.top_countries),
    top_source_ips: normalizeTopItems(data?.top_source_ips),
  }
}

export async function fetchHoneypotSessions(): Promise<HoneypotSession[]> {
  const data = await apiGet<any>(withTrailingSlash('/api/dashboard/honeypot/sessions'))
  const raw = toArray<HoneypotSession>(data?.sessions || data)
  return raw.map(parseSession)
}

export async function fetchHoneypotCredentials(): Promise<Array<{ username: string; password: string; count: number; source_ips: string[] }>> {
  const data = await apiGet<any>(withTrailingSlash('/api/dashboard/honeypot/credentials'))
  const raw = toArray<any>(data?.credentials || data)

  return raw.map((item) => ({
    username: String(item?.username || ''),
    password: String(item?.password || ''),
    count: toNumber(item?.count),
    source_ips: toArray<string>(item?.source_ips).map((ip) => String(ip)),
  }))
}
