import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getSessions, getSessionTimeline } from '../api/sessions'
import { Card, Skeleton, EmptyState, Modal } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import { formatRelativeTime } from '../lib/utils'
import type { Session } from '../types'

function riskColor(score: number): string {
  if (score >= 0.8) return 'bg-red-500'
  if (score >= 0.5) return 'bg-yellow-500'
  return 'bg-green-500'
}

export default function Sessions() {
  const [filter, setFilter] = useState('')
  const [selectedSession, setSelectedSession] = useState<Session | null>(null)
  const { data: sessions, isLoading } = useQuery({ queryKey: ['sessions'], queryFn: getSessions })

  const filtered = sessions?.filter(
    (s) =>
      s.sessionId.toLowerCase().includes(filter.toLowerCase()) ||
      s.agentId.toLowerCase().includes(filter.toLowerCase())
  ) || []

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Active Sessions</h1>
          <p className="text-slate-500">Recently active agent sessions and risk scores</p>
        </div>
      </div>

      <div className="flex gap-3">
        <input
          placeholder="Filter by session or agent ID..."
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="max-w-sm px-3 py-2 border border-slate-300 rounded-md"
        />
        <span className="text-sm text-slate-600 self-center">{filtered.length} active session{filtered.length !== 1 ? 's' : ''}</span>
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : filtered.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Session ID</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Tool Calls</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Last Active</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((s) => (
                <TableRow
                  key={s.sessionId}
                  className="cursor-pointer hover:bg-slate-50"
                  onClick={() => setSelectedSession(s)}
                >
                  <TableCell>
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{s.sessionId}</code>
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{s.agentId}</code>
                  </TableCell>
                  <TableCell>{s.toolCallCount}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-3">
                      <span className={`text-sm font-semibold ${s.riskScore >= 0.8 ? 'text-red-600' : s.riskScore >= 0.5 ? 'text-yellow-600' : 'text-green-600'}`}>
                        {(s.riskScore * 100).toFixed(0)}%
                      </span>
                      <div className="w-24 h-2 bg-slate-200 rounded-full overflow-hidden">
                        <div className={`h-full ${riskColor(s.riskScore)}`} style={{ width: `${Math.min(s.riskScore * 100, 100)}%` }} />
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>{formatRelativeTime(s.lastActive)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState message="No active sessions" />
        )}
      </Card>

      {selectedSession && (
        <SessionTimelineModal
          session={selectedSession}
          onClose={() => setSelectedSession(null)}
        />
      )}
    </div>
  )
}

function SessionTimelineModal({ session, onClose }: { session: Session; onClose: () => void }) {
  const { data: timeline, isLoading } = useQuery({
    queryKey: ['session-timeline', session.sessionId],
    queryFn: () => getSessionTimeline(session.sessionId),
  })

  return (
    <Modal isOpen={true} onClose={onClose} title="Session Timeline" size="lg">
      <div className="space-y-4">
        <div className="text-sm text-slate-600">
          Session <code>{session.sessionId}</code> • Agent <code>{session.agentId}</code>
        </div>
        {isLoading ? (
          <Skeleton className="h-48" />
        ) : timeline?.length ? (
          <div className="space-y-3 max-h-96 overflow-auto">
            {timeline.map((item, idx) => (
              <div key={idx} className="flex gap-4 p-3 rounded-lg border border-slate-200">
                <div className="text-xs text-slate-500 whitespace-nowrap">
                  {new Date(item.timestamp).toLocaleTimeString()}
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{item.tool}</code>
                    <span className={`text-xs font-medium px-2 py-0.5 rounded ${
                      item.decision === 'blocked' ? 'bg-red-100 text-red-800' :
                      item.decision === 'flagged' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>{item.decision}</span>
                  </div>
                  <p className="text-sm text-slate-700 mt-1">{item.reason}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState message="No timeline data" />
        )}
      </div>
    </Modal>
  )
}
