import { apiGet, apiPatch, withTrailingSlash } from './api'

export interface AlertItem {
  id: string
  created_at?: string
  rule_name?: string
  rule_id?: string
  severity?: string
  status?: string
  description?: string
}

function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

export async function fetchAlerts(status?: string): Promise<AlertItem[]> {
  const params = new URLSearchParams()
  if (status) {
    params.set('status', status)
  }

  const query = params.toString()
  const endpoint = `${withTrailingSlash('/api/alerts')}${query ? `?${query}` : ''}`
  const data = await apiGet<any>(endpoint)

  return toArray<AlertItem>(data?.alerts || data)
}

export async function updateAlertStatus(alertId: string, status: string): Promise<void> {
  await apiPatch<void, { status: string }>(`/api/alerts/${alertId}`, { status })
}
