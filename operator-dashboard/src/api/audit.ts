import { apiClient } from './client'
import type { AuditListResponse, EventHistogram, FilterParams } from '../types'

export async function getAuditEvents(params: FilterParams = {}): Promise<AuditListResponse> {
  const search = new URLSearchParams()
  if (params.agentId) search.set('agent_id', params.agentId)
  if (params.action) search.set('action', params.action)
  if (params.startDate) search.set('from', params.startDate)
  if (params.endDate) search.set('to', params.endDate)
  if (params.search) search.set('search', params.search)
  if (params.page) search.set('page', params.page.toString())
  if (params.pageSize) search.set('page_size', params.pageSize.toString())
  return apiClient.get<AuditListResponse>(`/admin/audit?${search.toString()}`)
}

export async function getEventHistogram(range: string = '1h'): Promise<EventHistogram> {
  return apiClient.get<EventHistogram>(`/admin/audit/histogram?range=${range}`)
}

export function exportAuditCsvUrl(): string {
  return '/admin/audit/export?format=csv'
}
