import { useQuery } from '@tanstack/react-query'
import { getAnalytics } from '../api/analytics'
import { Card, Skeleton, EmptyState } from '../components/ui'
import { formatNumber, formatPercent } from '../lib/utils'

export default function Analytics() {
  const { data, isLoading } = useQuery({ queryKey: ['analytics'], queryFn: getAnalytics })

  if (isLoading) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-slate-900">Analytics</h1>
        <Skeleton className="h-32" />
        <Skeleton className="h-64" />
      </div>
    )
  }

  const aggregate = data?.aggregate
  const agents = data?.perAgent || []
  const cacheHitRate = data?.cacheHitRate || 0

  const total = aggregate?.totalCalls || 1
  const allowPct = aggregate ? (aggregate.allowCount / total) * 100 : 0
  const blockPct = aggregate ? (aggregate.blockCount / total) * 100 : 0
  const flagPct = aggregate ? (aggregate.flagCount / total) * 100 : 0

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-slate-900">Analytics</h1>

      {aggregate ? (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard label="Total Calls" value={formatNumber(aggregate.totalCalls)} color="blue" />
            <StatCard label="Allow Rate" value={formatPercent(allowPct)} color="green" />
            <StatCard label="Block Rate" value={formatPercent(blockPct)} color="red" />
            <StatCard label="Flag Rate" value={formatPercent(flagPct)} color="yellow" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <StatCard label="Avg Latency" value={`${aggregate.avgLatencyMs.toFixed(1)}ms`} color="slate" />
            <StatCard label="Cache Hit Rate" value={formatPercent(cacheHitRate * 100)} color="slate" />
          </div>
        </>
      ) : (
        <EmptyState message="No analytics data available" />
      )}

      <Card title="Per-Agent Breakdown">
        {agents.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-slate-50">
                <tr>
                  <th className="text-left px-4 py-2 font-medium text-slate-600">Agent</th>
                  <th className="text-right px-4 py-2 font-medium text-slate-600">Total</th>
                  <th className="text-right px-4 py-2 font-medium text-slate-600">Allow</th>
                  <th className="text-right px-4 py-2 font-medium text-slate-600">Block</th>
                  <th className="text-right px-4 py-2 font-medium text-slate-600">Flag</th>
                  <th className="text-right px-4 py-2 font-medium text-slate-600">Latency</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agentId} className="border-t border-slate-100">
                    <td className="px-4 py-2">
                      <div className="font-medium text-slate-900">{a.name}</div>
                      <div className="text-xs text-slate-500 font-mono">{a.agentId}</div>
                    </td>
                    <td className="px-4 py-2 text-right">{formatNumber(a.totalCalls)}</td>
                    <td className="px-4 py-2 text-right text-green-700">{formatNumber(a.allowCount)}</td>
                    <td className="px-4 py-2 text-right text-red-700">{formatNumber(a.blockCount)}</td>
                    <td className="px-4 py-2 text-right text-yellow-700">{formatNumber(a.flagCount)}</td>
                    <td className="px-4 py-2 text-right">{a.avgLatencyMs.toFixed(1)}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState message="No agent data" />
        )}
      </Card>
    </div>
  )
}

function StatCard({ label, value, color }: { label: string; value: string; color: 'blue' | 'green' | 'red' | 'yellow' | 'slate' }) {
  const styles = {
    blue: 'bg-blue-50 border-blue-200 text-blue-900',
    green: 'bg-green-50 border-green-200 text-green-900',
    red: 'bg-red-50 border-red-200 text-red-900',
    yellow: 'bg-yellow-50 border-yellow-200 text-yellow-900',
    slate: 'bg-slate-50 border-slate-200 text-slate-900',
  }
  return (
    <div className={`rounded-lg border p-4 ${styles[color]}`}>
      <div className="text-xs font-semibold uppercase tracking-wide opacity-80">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
  )
}
