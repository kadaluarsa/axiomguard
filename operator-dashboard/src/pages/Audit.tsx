import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAuditEvents, getEventHistogram, exportAuditCsvUrl } from '../api/audit'
import { Card, Button, Badge, Skeleton, EmptyState } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import { formatDateTime, formatNumber } from '../lib/utils'
import type { EventHistogram } from '../types'

const ACTION_OPTIONS = ['', 'blocked', 'allowed', 'flagged', 'modified']
const RANGE_OPTIONS = [
  { value: '15m', label: '15 min' },
  { value: '30m', label: '30 min' },
  { value: '1h', label: '1 hour' },
  { value: '6h', label: '6 hours' },
  { value: '24h', label: '24 hours' },
  { value: '7d', label: '7 days' },
]

export default function Audit() {
  const [agentFilter, setAgentFilter] = useState('')
  const [actionFilter, setActionFilter] = useState('')
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const pageSize = 20
  const [range, setRange] = useState('1h')

  const { data: auditData, isLoading } = useQuery({
    queryKey: ['audit', agentFilter, actionFilter, search, page],
    queryFn: () =>
      getAuditEvents({
        agentId: agentFilter || undefined,
        action: (actionFilter as any) || undefined,
        search: search || undefined,
        page,
        pageSize,
      }),
  })

  const { data: histogram } = useQuery({
    queryKey: ['audit-histogram', range],
    queryFn: () => getEventHistogram(range),
  })

  const events = auditData?.events || []
  const total = auditData?.total || 0
  const totalPages = Math.max(1, Math.ceil(total / pageSize))

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Audit Log</h1>
          <p className="text-slate-500">Security decisions and events from the control plane</p>
        </div>
        <Button variant="outline" onClick={() => window.open(exportAuditCsvUrl(), '_blank')}>
          Export CSV
        </Button>
      </div>

      {histogram && <HistogramChart histogram={histogram} range={range} onRangeChange={setRange} />}

      <div className="flex flex-wrap gap-3">
        <input
          placeholder="Agent ID..."
          value={agentFilter}
          onChange={(e) => { setAgentFilter(e.target.value); setPage(1) }}
          className="px-3 py-2 border border-slate-300 rounded-md text-sm"
        />
        <select
          value={actionFilter}
          onChange={(e) => { setActionFilter(e.target.value); setPage(1) }}
          className="px-3 py-2 border border-slate-300 rounded-md text-sm"
        >
          <option value="">All Actions</option>
          {ACTION_OPTIONS.slice(1).map((a) => (
            <option key={a} value={a}>{a}</option>
          ))}
        </select>
        <input
          placeholder="Search path or rule..."
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1) }}
          className="px-3 py-2 border border-slate-300 rounded-md text-sm"
        />
        <span className="text-sm text-slate-600 self-center ml-auto">
          {formatNumber(total)} total events
        </span>
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : events.length ? (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Agent</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Event Type</TableHead>
                  <TableHead>Latency</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="whitespace-nowrap text-sm">
                      {formatDateTime(e.timestamp)}
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">
                        {(e.data?.agentId as string) || '—'}
                      </code>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className={
                          (e.data?.action as string) === 'blocked'
                            ? 'text-red-700 border-red-200 bg-red-50'
                            : (e.data?.action as string) === 'flagged'
                            ? 'text-yellow-700 border-yellow-200 bg-yellow-50'
                            : 'text-green-700 border-green-200 bg-green-50'
                        }
                      >
                        {(e.data?.action as string) || 'allowed'}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-slate-700">{e.eventType}</TableCell>
                    <TableCell className="text-sm">
                      {e.processingTimeMs ? `${e.processingTimeMs.toFixed(1)}ms` : '—'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="flex items-center justify-between px-4 py-3 border-t border-slate-200">
              <Button
                variant="outline"
                size="sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                Previous
              </Button>
              <span className="text-sm text-slate-600">
                Page {page} of {totalPages}
              </span>
              <Button
                variant="outline"
                size="sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </>
        ) : (
          <EmptyState message="No audit events found" />
        )}
      </Card>
    </div>
  )
}

function HistogramChart({
  histogram,
  range,
  onRangeChange,
}: {
  histogram: EventHistogram
  range: string
  onRangeChange: (r: string) => void
}) {
  const max = Math.max(...histogram.buckets.map((b) => b.total), 1)

  return (
    <Card title="Event Histogram">
      <div className="space-y-3">
        <div className="flex gap-2">
          {RANGE_OPTIONS.map((r) => (
            <button
              key={r.value}
              onClick={() => onRangeChange(r.value)}
              className={`px-2 py-1 text-xs rounded-md border transition-colors ${
                range === r.value
                  ? 'bg-blue-100 border-blue-300 text-blue-800'
                  : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50'
              }`}
            >
              {r.label}
            </button>
          ))}
        </div>
        <div className="flex items-end gap-1 h-32">
          {histogram.buckets.map((b, i) => (
            <div key={i} className="flex-1 flex flex-col justify-end group relative">
              <div
                className="w-full rounded-sm overflow-hidden"
                style={{ height: `${(b.total / max) * 100}%` }}
              >
                <div
                  className="w-full bg-red-500"
                  style={{ height: `${b.total ? (b.blocked / b.total) * 100 : 0}%` }}
                />
                <div
                  className="w-full bg-yellow-500"
                  style={{ height: `${b.total ? (b.flagged / b.total) * 100 : 0}%` }}
                />
                <div
                  className="w-full bg-green-500"
                  style={{ height: `${b.total ? (b.allowed / b.total) * 100 : 0}%` }}
                />
              </div>
              <div className="opacity-0 group-hover:opacity-100 absolute bottom-full left-1/2 -translate-x-1/2 mb-1 px-2 py-1 bg-slate-900 text-white text-xs rounded whitespace-nowrap pointer-events-none z-10">
                {new Date(b.timestamp).toLocaleTimeString()}: {b.total} events
              </div>
            </div>
          ))}
        </div>
        <div className="flex gap-4 text-xs">
          <div className="flex items-center gap-1"><div className="w-3 h-3 bg-red-500 rounded-sm" /> Blocked</div>
          <div className="flex items-center gap-1"><div className="w-3 h-3 bg-yellow-500 rounded-sm" /> Flagged</div>
          <div className="flex items-center gap-1"><div className="w-3 h-3 bg-green-500 rounded-sm" /> Allowed</div>
        </div>
      </div>
    </Card>
  )
}
