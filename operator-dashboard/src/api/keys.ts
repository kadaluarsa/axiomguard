import { apiClient } from './client'
import type { ApiKey, CreateApiKeyRequest, RotateKeyRequest } from '../types'

export async function getApiKeys(): Promise<ApiKey[]> {
  return apiClient.get<ApiKey[]>('/admin/keys')
}

export async function createApiKey(request: CreateApiKeyRequest): Promise<{ apiKey: ApiKey; fullKey: string }> {
  return apiClient.post<{ apiKey: ApiKey; fullKey: string }>('/admin/keys', request)
}

export async function rotateApiKey(id: string, request: RotateKeyRequest): Promise<{ oldKey: ApiKey; newKey: ApiKey; fullKey: string; gracePeriodEndsAt: string }> {
  return apiClient.post<{ oldKey: ApiKey; newKey: ApiKey; fullKey: string; gracePeriodEndsAt: string }>(`/admin/keys/${id}/rotate`, request)
}

export async function revokeApiKey(id: string): Promise<ApiKey> {
  return apiClient.post<ApiKey>(`/admin/keys/${id}/revoke`, {})
}

export async function deleteApiKey(id: string): Promise<void> {
  return apiClient.delete<void>(`/admin/keys/${id}`)
}
