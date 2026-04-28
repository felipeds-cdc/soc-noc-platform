import { apiGet, withTrailingSlash } from './api'

export interface EventsFilters {
  severity?: string
  event_type?: string
  source_ip?: string
}

export interface SecurityEvent {
  id?: string
  timestamp?: string
  event_type?: string
  severity?: string
  source_ip?: string
  username?: string
  mitre_technique_id?: string
  source?: string
}

function toArray<T>(value: unknown): T[] {
  return Array.isArray(value) ? (value as T[]) : []
}

export async function fetchEvents(filters: EventsFilters): Promise<SecurityEvent[]> {
  const params = new URLSearchParams()

  if (filters.severity) params.set('severity', filters.severity)
  if (filters.event_type) params.set('event_type', filters.event_type)
  if (filters.source_ip) params.set('source_ip', filters.source_ip)

  const query = params.toString()
  const endpoint = `${withTrailingSlash('/api/events')}${query ? `?${query}` : ''}`
  const data = await apiGet<any>(endpoint)

  return toArray<SecurityEvent>(data?.events || data)
}
