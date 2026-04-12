import { apiClient } from './client'
import type { AnalyticsResponse } from '../types'

export async function getAnalytics(): Promise<AnalyticsResponse> {
  return apiClient.get<AnalyticsResponse>('/admin/analytics')
}
