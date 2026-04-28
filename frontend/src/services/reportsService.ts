import { apiPost } from './api'

export interface GeneratedReport {
  content: string
  generated_at?: string
}

export interface ReportPayload {
  report_type: string
  format: string
  include_recommendations: boolean
  include_iocs: boolean
}

export async function generateSecurityReport(payload: ReportPayload): Promise<GeneratedReport> {
  const data = await apiPost<any, ReportPayload>('/api/reports/generate', payload)

  return {
    content: String(data?.content || ''),
    generated_at: typeof data?.generated_at === 'string' ? data.generated_at : undefined,
  }
}
