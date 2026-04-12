import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Copy, Check, RefreshCw, Trash2, X } from 'lucide-react'
import { getApiKeys, createApiKey, rotateApiKey, revokeApiKey, deleteApiKey } from '../api/keys'
import { getAgents } from '../api/agents'
import { Card, Button, Badge, Modal, Input, Skeleton, EmptyState } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import { formatRelativeTime, copyToClipboard } from '../lib/utils'
import type { ApiKey } from '../types'
import { toast } from 'sonner'

export default function Keys() {
  const [isCreateOpen, setIsCreateOpen] = useState(false)
  const [revealedKey, setRevealedKey] = useState<{ key: ApiKey; fullKey: string } | null>(null)
  const queryClient = useQueryClient()

  const { data: keys, isLoading } = useQuery({ queryKey: ['keys'], queryFn: getApiKeys })

  const revokeMutation = useMutation({
    mutationFn: revokeApiKey,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteApiKey,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['keys'] }),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">API Keys</h1>
          <p className="text-slate-500">Manage keys for SDK and tool wrapper authentication</p>
        </div>
        <Button onClick={() => setIsCreateOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Key
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : keys?.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Agent</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.map((key) => (
                <TableRow key={key.id}>
                  <TableCell className="font-medium">{key.name}</TableCell>
                  <TableCell>
                    <code className="text-xs bg-slate-100 px-1.5 py-0.5 rounded">{key.keyPrefix}</code>
                  </TableCell>
                  <TableCell>
                    <KeyStatusBadge status={key.status} gracePeriodEndsAt={key.gracePeriodEndsAt} />
                  </TableCell>
                  <TableCell>{key.agentName || key.agentId || '—'}</TableCell>
                  <TableCell>{formatRelativeTime(key.createdAt)}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      {key.status === 'active' && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            if (!confirm(`Rotate key "${key.name}"?`)) return
                            rotateApiKey(key.id, { gracePeriodHours: 24, revokeOldImmediately: false }).then((res) => {
                              setRevealedKey({ key: res.newKey, fullKey: res.fullKey })
                              queryClient.invalidateQueries({ queryKey: ['keys'] })
                            })
                          }}
                        >
                          <RefreshCw className="h-4 w-4" />
                        </Button>
                      )}
                      {key.status !== 'revoked' && (
                        <Button variant="ghost" size="sm" onClick={() => confirm(`Revoke "${key.name}"?`) && revokeMutation.mutate(key.id)}>
                          <X className="h-4 w-4 text-red-600" />
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" onClick={() => confirm(`Delete "${key.name}"?`) && deleteMutation.mutate(key.id)}>
                        <Trash2 className="h-4 w-4 text-slate-600" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            title="No API keys"
            description="Create an API key to authenticate agents"
            icon="shield"
            action={
              <Button onClick={() => setIsCreateOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Create Key
              </Button>
            }
          />
        )}
      </Card>

      <CreateKeyModal
        isOpen={isCreateOpen}
        onClose={() => setIsCreateOpen(false)}
        onCreated={(key, fullKey) => {
          setRevealedKey({ key, fullKey })
          queryClient.invalidateQueries({ queryKey: ['keys'] })
        }}
      />

      {revealedKey && (
        <RevealKeyModal
          apiKey={revealedKey.key}
          fullKey={revealedKey.fullKey}
          onClose={() => setRevealedKey(null)}
        />
      )}
    </div>
  )
}

function KeyStatusBadge({ status, gracePeriodEndsAt }: { status: string; gracePeriodEndsAt?: string }) {
  const colors: Record<string, string> = {
    active: 'bg-green-100 text-green-800',
    rotating: 'bg-yellow-100 text-yellow-800',
    expiring: 'bg-orange-100 text-orange-800',
    expired: 'bg-slate-100 text-slate-800',
    revoked: 'bg-red-100 text-red-800',
  }
  return (
    <div className="flex flex-col">
      <Badge className={colors[status] || colors.active}>{status}</Badge>
      {status === 'rotating' && gracePeriodEndsAt && (
        <span className="text-xs text-slate-500 mt-0.5">Grace ends {formatRelativeTime(gracePeriodEndsAt)}</span>
      )}
    </div>
  )
}

function CreateKeyModal({
  isOpen,
  onClose,
  onCreated,
}: {
  isOpen: boolean
  onClose: () => void
  onCreated: (key: ApiKey, fullKey: string) => void
}) {
  const [name, setName] = useState('')
  const [agentId, setAgentId] = useState('')
  const [expiresInDays, setExpiresInDays] = useState<number | ''>('')
  const [permissions, setPermissions] = useState<string[]>(['read:events', 'write:rules'])
  const [isLoading, setIsLoading] = useState(false)
  const { data: agents } = useQuery({ queryKey: ['agents'], queryFn: getAgents, enabled: isOpen })

  const PERMISSION_OPTIONS = ['read:events', 'write:rules', 'read:stats', 'admin:agents', 'admin:keys']

  const togglePermission = (perm: string) => {
    setPermissions((prev) => (prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]))
  }

  const handleSubmit = async () => {
    if (!name) return
    setIsLoading(true)
    try {
      const res = await createApiKey({
        name,
        agentId: agentId || undefined,
        permissions,
        expiresInDays: expiresInDays ? Number(expiresInDays) : undefined,
      })
      onCreated(res.apiKey, res.fullKey)
      onClose()
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title="Create API Key"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSubmit} isLoading={isLoading}>Create</Button>
        </>
      }
    >
      <div className="space-y-4">
        <Input label="Name" value={name} onChange={(e) => setName(e.target.value)} required />
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Linked Agent</label>
          <select
            value={agentId}
            onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setAgentId(e.target.value)}
            className="w-full px-3 py-2 border border-slate-300 rounded-md"
          >
            <option value="">None</option>
            {agents?.map((a) => (
              <option key={a.id} value={a.id}>{a.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Expires In (days)</label>
          <input
            type="number"
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value === '' ? '' : parseInt(e.target.value))}
            placeholder="Never"
            className="w-full px-3 py-2 border border-slate-300 rounded-md"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">Permissions</label>
          <div className="space-y-2">
            {PERMISSION_OPTIONS.map((perm) => (
              <label key={perm} className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={permissions.includes(perm)}
                  onChange={() => togglePermission(perm)}
                />
                <span className="text-sm">{perm}</span>
              </label>
            ))}
          </div>
        </div>
      </div>
    </Modal>
  )
}

function RevealKeyModal({ apiKey, fullKey, onClose }: { apiKey: ApiKey; fullKey: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    const ok = await copyToClipboard(fullKey)
    if (ok) {
      setCopied(true)
      toast.success('Copied to clipboard')
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <Modal
      isOpen={true}
      onClose={onClose}
      title="API Key Created"
      size="md"
      footer={<Button onClick={onClose}>Done</Button>}
    >
      <div className="space-y-4">
        <div className="p-3 bg-yellow-50 border border-yellow-200 rounded-md text-sm text-yellow-800">
          Copy this key now. You won&apos;t be able to see it again.
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Key Name</label>
          <div className="text-slate-900">{apiKey.name}</div>
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-1">Full Key</label>
          <div className="flex gap-2">
            <code className="flex-1 bg-slate-100 p-3 rounded-md text-sm font-mono break-all">{fullKey}</code>
            <Button variant="outline" onClick={handleCopy}>
              {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  )
}
