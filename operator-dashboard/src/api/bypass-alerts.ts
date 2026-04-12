import { apiClient } from './client'
import type { BypassAlert } from '../types'

export async function getBypassAlerts(): Promise<BypassAlert[]> {
  return apiClient.get<BypassAlert[]>('/admin/bypass-alerts')
}
