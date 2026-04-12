import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getBypassAlerts } from '../api/bypass-alerts'
import { Card, Skeleton, EmptyState } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import type { BypassAlert } from '../types'

export default function BypassAlerts() {
  const [filter, setFilter] = useState('')
  const { data: alerts, isLoading } = useQuery({ queryKey: ['bypass-alerts'], queryFn: getBypassAlerts })

  const filtered = alerts?.filter(
    (a) =>
      a.agentId.toLowerCase().includes(filter.toLowerCase()) ||
      a.toolName.toLowerCase().includes(filter.toLowerCase()) ||
      a.reason.toLowerCase().includes(filter.toLowerCase())
  ) || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Bypass Alerts</h1>
          <p className="text-slate-500">Security events where tool wrappers detected bypass attempts</p>
        </div>
        <div className="flex items-center gap-2">
          <div className={`h-2.5 w-2.5 rounded-full ${filtered.length > 0 ? 'bg-red-500' : 'bg-slate-400'}`} />
          <span className="text-sm text-slate-600">{filtered.length} alert{filtered.length !== 1 ? 's' : ''}</span>
        </div>
      </div>

      <div className="flex gap-3">
        <input
          placeholder="Filter by agent, tool, or reason..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-sm px-3 py-2 border border-slate-300 rounded-md"
        />
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : filtered.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Tool</TableHead>
                <TableHead>Reason</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((alert) => (
                <TableRow key={alert.id}>
                  <TableCell className="whitespace-nowrap text-sm">
                    {new Date(alert.timestamp).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{alert.agentId}</code>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{alert.toolName}</code>
                  </TableCell>
                  <TableCell className="text-slate-700">{alert.reason}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState title="No bypass alerts" description="Great! No bypass attempts have been detected." icon="shield" />
        )}
      </Card>
    </div>
  )
}
