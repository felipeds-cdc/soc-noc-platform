import { apiGet, apiPost } from './api'

export interface ThreatSearchResponse {
  total_hits: number
  execution_time_ms: number
  results: unknown[]
}

export interface IpAnalysis {
  total_events: number
  associated_sessions: number
  geo_info?: {
    country?: string
  }
  event_types?: Record<string, number>
  commands_executed?: string[]
}

export async function searchThreats(query: string): Promise<ThreatSearchResponse> {
  const data = await apiPost<any, { query: string; time_range: string }>('/api/threat-hunting/search', {
    query,
    time_range: '24h',
  })

  return {
    total_hits: Number(data?.total_hits || 0),
    execution_time_ms: Number(data?.execution_time_ms || 0),
    results: Array.isArray(data?.results) ? data.results : [],
  }
}

export async function analyzeIpAddress(ip: string): Promise<IpAnalysis> {
  const data = await apiGet<any>(`/api/threat-hunting/ip-analysis/${encodeURIComponent(ip)}`)

  return {
    total_events: Number(data?.total_events || 0),
    associated_sessions: Number(data?.associated_sessions || 0),
    geo_info: data?.geo_info,
    event_types: data?.event_types || {},
    commands_executed: Array.isArray(data?.commands_executed) ? data.commands_executed : [],
  }
}
