import { useState } from 'react'
import { useAuthStore } from '../store/auth'
import { Button, Card } from '../components/ui'
import { Shield, Key } from 'lucide-react'

export default function Login() {
  const [apiKey, setApiKey] = useState('')
  const [tenantId, setTenantId] = useState('default')
  const [isLoading, setIsLoading] = useState(false)
  const setCredentials = useAuthStore((s) => s.setCredentials)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!apiKey.trim()) return
    setIsLoading(true)
    // In a real flow we might validate the key against /v1/health first.
    // For now we accept it and let subsequent requests fail with a toast if invalid.
    setTimeout(() => {
      setCredentials(apiKey.trim(), tenantId.trim() || 'default')
      setIsLoading(false)
    }, 300)
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
      <Card className="w-full max-w-md p-8">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-blue-600 rounded-lg">
            <Shield className="h-6 w-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-900">AxiomGuard</h1>
            <p className="text-sm text-slate-500">v4 Admin Dashboard</p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              API Key
            </label>
            <div className="relative">
              <Key className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="Enter your CP_API_KEY"
                className="w-full pl-9 pr-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Your API key is stored locally in your browser.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              Tenant ID
            </label>
            <input
              type="text"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              placeholder="default"
              className="w-full px-3 py-2 border border-slate-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <Button type="submit" className="w-full" isLoading={isLoading}>
            Sign In
          </Button>
        </form>
      </Card>
    </div>
  )
}
