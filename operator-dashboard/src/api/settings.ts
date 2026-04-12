import { apiClient } from './client'
import type { TenantSettings } from '../types'

export async function getSettings(): Promise<TenantSettings> {
  return apiClient.get<TenantSettings>('/admin/settings')
}

export async function updateSettings(settings: Partial<TenantSettings>): Promise<TenantSettings> {
  return apiClient.put<TenantSettings>('/admin/settings', settings)
}
