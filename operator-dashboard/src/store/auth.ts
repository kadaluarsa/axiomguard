import { create } from 'zustand'
import { getStorageItem, setStorageItem } from '../lib/utils'

interface AuthState {
  apiKey: string | null
  tenantId: string | null
  isAuthenticated: boolean
  setCredentials: (apiKey: string, tenantId?: string) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>((set) => ({
  apiKey: getStorageItem('ag_api_key', ''),
  tenantId: getStorageItem('ag_tenant_id', 'default'),
  isAuthenticated: !!getStorageItem('ag_api_key', ''),

  setCredentials: (apiKey, tenantId = 'default') => {
    setStorageItem('ag_api_key', apiKey)
    setStorageItem('ag_tenant_id', tenantId)
    set({ apiKey, tenantId, isAuthenticated: true })
  },

  logout: () => {
    setStorageItem('ag_api_key', '')
    setStorageItem('ag_tenant_id', 'default')
    set({ apiKey: null, tenantId: null, isAuthenticated: false })
  },
}))
