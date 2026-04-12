import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter, Routes, Route, NavLink, Navigate, Outlet } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Toaster } from 'sonner'
import { useAuthStore } from './store/auth'

// Pages
import Login from './pages/Login'
import AgentsPage from './pages/Agents'
import RulesPage from './pages/Rules'
import SessionsPage from './pages/Sessions'
import AuditPage from './pages/Audit'
import AnalyticsPage from './pages/Analytics'
import KeysPage from './pages/Keys'
import BypassAlertsPage from './pages/BypassAlerts'

import './index.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

const navItems = [
  { to: '/agents', label: 'Agents' },
  { to: '/rules', label: 'Rules' },
  { to: '/sessions', label: 'Sessions' },
  { to: '/audit', label: 'Audit' },
  { to: '/analytics', label: 'Analytics' },
  { to: '/keys', label: 'Keys' },
  { to: '/bypass-alerts', label: 'Bypass Alerts' },
]

function AuthGuard() {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  return isAuthenticated ? <Outlet /> : <Navigate to="/login" replace />
}

function Layout() {
  return (
    <div className="flex min-h-screen bg-white">
      <nav className="w-56 border-r border-slate-200 p-4 bg-slate-50 flex flex-col">
        <div className="text-lg font-bold text-slate-900 mb-6 px-2">AxiomGuard</div>
        <div className="flex-1 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `block px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-100 text-blue-800'
                    : 'text-slate-600 hover:bg-slate-100'
                }`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </div>
        <div className="pt-4 border-t border-slate-200">
          <button
            onClick={() => useAuthStore.getState().logout()}
            className="w-full text-left px-3 py-2 text-sm text-slate-600 hover:bg-slate-100 rounded-md"
          >
            Sign Out
          </button>
        </div>
      </nav>
      <main className="flex-1 p-6 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route element={<AuthGuard />}>
            <Route element={<Layout />}>
              <Route path="/" element={<Navigate to="/agents" replace />} />
              <Route path="/agents" element={<AgentsPage />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/sessions" element={<SessionsPage />} />
              <Route path="/audit" element={<AuditPage />} />
              <Route path="/analytics" element={<AnalyticsPage />} />
              <Route path="/keys" element={<KeysPage />} />
              <Route path="/bypass-alerts" element={<BypassAlertsPage />} />
            </Route>
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster position="top-right" richColors />
    </QueryClientProvider>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
)
