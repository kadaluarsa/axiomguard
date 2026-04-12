import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus,
  Trash2,
  Check,
  X,
} from 'lucide-react'
import { Card, Button, Badge, Modal, Input, Skeleton, EmptyState } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import { Tabs, TabList, Tab, TabPanel } from '../components/ui/Tabs'
import { getAgents, createAgent, deleteAgent, getAgentRules, assignAgentRule, unassignAgentRule } from '../api/agents'
import { getRules } from '../api/rules'
import { formatNumber, formatRelativeTime, cn } from '../lib/utils'
import type { Agent, ToolPermission } from '../types'

const TOOL_OPTIONS = ['read_file', 'write_file', 'execute', 'network', 'http_request', 'database_query']

export default function Agents() {
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null)
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false)
  const queryClient = useQueryClient()

  const { data: agents, isLoading } = useQuery({ queryKey: ['agents'], queryFn: getAgents })

  const createMutation = useMutation({
    mutationFn: createAgent,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agents'] })
      setIsCreateModalOpen(false)
    },
  })

  const deleteMutation = useMutation({
    mutationFn: deleteAgent,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['agents'] }),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Agents</h1>
          <p className="text-slate-500">Manage integration agents and their security posture</p>
        </div>
        <Button onClick={() => setIsCreateModalOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Agent
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : agents?.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Tools</TableHead>
                <TableHead>Risk Threshold</TableHead>
                <TableHead>Quota (daily/burst)</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {agents.map((agent) => (
                <AgentRow
                  key={agent.id}
                  agent={agent}
                  onClick={() => {
                    setSelectedAgent(agent)
                    setIsDetailModalOpen(true)
                  }}
                  onDelete={() => {
                    if (confirm(`Delete "${agent.name}"?`)) deleteMutation.mutate(agent.id)
                  }}
                />
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            title="No agents yet"
            description="Create your first agent to start integrating with AxiomGuard"
            icon="shield"
            action={
              <Button onClick={() => setIsCreateModalOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Create Agent
              </Button>
            }
          />
        )}
      </Card>

      <CreateAgentModal
        isOpen={isCreateModalOpen}
        onClose={() => setIsCreateModalOpen(false)}
        onCreate={(data) => createMutation.mutate(data as Agent)}
        isLoading={createMutation.isPending}
      />

      {selectedAgent && (
        <AgentDetailModal
          agent={selectedAgent}
          isOpen={isDetailModalOpen}
          onClose={() => {
            setIsDetailModalOpen(false)
            setSelectedAgent(null)
          }}
        />
      )}
    </div>
  )
}

function AgentRow({ agent, onClick, onDelete }: { agent: Agent; onClick: () => void; onDelete: () => void }) {
  const tools = Object.keys(agent.toolAllowlist || {})
  return (
    <TableRow className="cursor-pointer hover:bg-slate-50" onClick={onClick}>
      <TableCell>
        <div>
          <p className="font-medium text-slate-900">{agent.name}</p>
          <p className="text-xs text-slate-500 font-mono">{agent.id}</p>
        </div>
      </TableCell>
      <TableCell>
        <div className="flex flex-wrap gap-1">
          {tools.slice(0, 3).map((t) => (
            <Badge key={t} variant="secondary" className="text-xs">{t}</Badge>
          ))}
          {tools.length > 3 && <Badge variant="outline" className="text-xs">+{tools.length - 3}</Badge>}
        </div>
      </TableCell>
      <TableCell>{agent.riskThreshold}</TableCell>
      <TableCell>{formatNumber(agent.quotaMaxDaily)} / {formatNumber(agent.quotaMaxBurst)}</TableCell>
      <TableCell>{formatRelativeTime(agent.createdAt)}</TableCell>
      <TableCell className="text-right">
        <div className="flex justify-end gap-2" onClick={(e) => e.stopPropagation()}>
          <Button variant="ghost" size="sm" onClick={onDelete}>
            <Trash2 className="h-4 w-4 text-red-600" />
          </Button>
        </div>
      </TableCell>
    </TableRow>
  )
}

function CreateAgentModal({
  isOpen,
  onClose,
  onCreate,
  isLoading,
}: {
  isOpen: boolean
  onClose: () => void
  onCreate: (data: Partial<Agent>) => void
  isLoading: boolean
}) {
  const [formData, setFormData] = useState<Partial<Agent>>({
    toolAllowlist: {},
    riskThreshold: 0.5,
    quotaMaxDaily: 10000,
    quotaMaxBurst: 100,
  })
  const [selectedTools, setSelectedTools] = useState<Record<string, ToolPermission>>({})

  const toggleTool = (tool: string) => {
    setSelectedTools((prev) => {
      const next = { ...prev }
      if (next[tool]) delete next[tool]
      else next[tool] = { type: 'Allow' }
      return next
    })
  }

  const handleSubmit = () => {
    if (formData.name) {
      onCreate({ ...formData, toolAllowlist: selectedTools, id: `agent_${Date.now()}`, tenantId: 'default' })
    }
  }

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Create Agent" size="lg" footer={
      <>
        <Button variant="outline" onClick={onClose}>Cancel</Button>
        <Button onClick={handleSubmit} isLoading={isLoading}>Create Agent</Button>
      </>
    }>
      <div className="space-y-4">
        <Input
          label="Agent Name"
          placeholder="e.g. Production Agent"
          value={formData.name || ''}
          onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
          required
        />
        <div>
          <label className="block text-sm font-medium text-slate-700 mb-2">Tool Allowlist</label>
          <div className="flex flex-wrap gap-2">
            {TOOL_OPTIONS.map((tool) => {
              const selected = !!selectedTools[tool]
              return (
                <button
                  key={tool}
                  type="button"
                  onClick={() => toggleTool(tool)}
                  className={cn(
                    'px-3 py-1.5 rounded-full text-sm border transition-colors',
                    selected ? 'bg-blue-100 border-blue-300 text-blue-800' : 'bg-white border-slate-300 text-slate-700 hover:bg-slate-50'
                  )}
                >
                  {selected && <Check className="inline h-3 w-3 mr-1" />}
                  {tool}
                </button>
              )
            })}
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Risk Threshold</label>
            <input
              type="range"
              min={0}
              max={1}
              step={0.1}
              value={formData.riskThreshold}
              onChange={(e) => setFormData((d) => ({ ...d, riskThreshold: parseFloat(e.target.value) }))}
              className="w-full"
            />
            <div className="text-sm text-slate-600 mt-1">{formData.riskThreshold}</div>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Daily Quota</label>
            <input
              type="number"
              value={formData.quotaMaxDaily}
              onChange={(e) => setFormData((d) => ({ ...d, quotaMaxDaily: parseInt(e.target.value) }))}
              className="w-full px-3 py-2 border border-slate-300 rounded-md"
            />
          </div>
        </div>
      </div>
    </Modal>
  )
}

function AgentDetailModal({ agent, isOpen, onClose }: { agent: Agent; isOpen: boolean; onClose: () => void }) {
  return (
    <Modal isOpen={isOpen} onClose={onClose} title={agent.name} description={agent.id} size="xl">
      <Tabs defaultTab="overview">
        <TabList>
          <Tab value="overview">Overview</Tab>
          <Tab value="rules">Rules</Tab>
          <Tab value="integration">Integration</Tab>
        </TabList>
        <TabPanel value="overview">
          <AgentOverviewTab agent={agent} />
        </TabPanel>
        <TabPanel value="rules">
          <AgentRulesTab agent={agent} />
        </TabPanel>
        <TabPanel value="integration">
          <AgentIntegrationTab agent={agent} />
        </TabPanel>
      </Tabs>
    </Modal>
  )
}

function AgentOverviewTab({ agent }: { agent: Agent }) {
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4">
        <Card>
          <div className="p-4">
            <p className="text-sm text-slate-500">Risk Threshold</p>
            <p className="text-xl font-semibold">{agent.riskThreshold}</p>
          </div>
        </Card>
        <Card>
          <div className="p-4">
            <p className="text-sm text-slate-500">Daily Quota</p>
            <p className="text-xl font-semibold">{formatNumber(agent.quotaMaxDaily)}</p>
          </div>
        </Card>
      </div>
      <div>
        <h4 className="font-medium mb-3">Tool Allowlist</h4>
        <div className="flex flex-wrap gap-2">
          {Object.entries(agent.toolAllowlist || {}).map(([tool, perm]) => (
            <Badge key={tool} variant="outline">
              {tool}: {perm.type}
            </Badge>
          ))}
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4 text-sm">
        <div>
          <span className="text-slate-500">Created:</span>{' '}
          {new Date(agent.createdAt).toLocaleString()}
        </div>
        <div>
          <span className="text-slate-500">Updated:</span>{' '}
          {new Date(agent.updatedAt).toLocaleString()}
        </div>
      </div>
    </div>
  )
}

function AgentRulesTab({ agent }: { agent: Agent }) {
  const queryClient = useQueryClient()
  const [isAssigning, setIsAssigning] = useState(false)

  const { data: bindings } = useQuery({
    queryKey: ['agent-rules', agent.id],
    queryFn: () => getAgentRules(agent.id),
  })

  const { data: allRules } = useQuery({
    queryKey: ['rules'],
    queryFn: getRules,
    enabled: isAssigning,
  })

  const assignMutation = useMutation({
    mutationFn: (ruleId: string) => assignAgentRule(agent.id, ruleId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['agent-rules', agent.id] }),
  })

  const unassignMutation = useMutation({
    mutationFn: (ruleId: string) => unassignAgentRule(agent.id, ruleId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['agent-rules', agent.id] }),
  })

  const boundRuleIds = new Set(bindings?.map((b) => b.ruleId) || [])

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h4 className="font-medium">Assigned Rules</h4>
        <Button size="sm" onClick={() => setIsAssigning(true)}>
          <Plus className="h-4 w-4 mr-1" />
          Assign Rule
        </Button>
      </div>

      {bindings?.length ? (
        <div className="space-y-2">
          {bindings.map((b) => {
            const rule = allRules?.find((r) => r.id === b.ruleId)
            return (
              <div key={b.ruleId} className="flex items-center justify-between p-3 rounded-lg border border-slate-200">
                <div>
                  <p className="font-medium">{rule?.name || b.ruleId}</p>
                  {b.priorityOverride != null && (
                    <p className="text-xs text-slate-500">Priority override: {b.priorityOverride}</p>
                  )}
                </div>
                <Button variant="ghost" size="sm" onClick={() => unassignMutation.mutate(b.ruleId)}>
                  <X className="h-4 w-4" />
                </Button>
              </div>
            )
          })}
        </div>
      ) : (
        <EmptyState message="No rules assigned" />
      )}

      {isAssigning && allRules && (
        <Modal
          isOpen={isAssigning}
          onClose={() => setIsAssigning(false)}
          title="Assign Rules"
          footer={
            <Button variant="outline" onClick={() => setIsAssigning(false)}>
              Done
            </Button>
          }
        >
          <div className="space-y-2 max-h-96 overflow-auto">
            {allRules
              .filter((r) => !boundRuleIds.has(r.id))
              .map((rule) => (
                <div
                  key={rule.id}
                  className="flex items-center justify-between p-3 rounded-lg border border-slate-200 hover:bg-slate-50"
                >
                  <div>
                    <p className="font-medium">{rule.name}</p>
                    <p className="text-sm text-slate-500">{rule.description}</p>
                  </div>
                  <Button size="sm" onClick={() => assignMutation.mutate(rule.id)}>
                    Assign
                  </Button>
                </div>
              ))}
          </div>
        </Modal>
      )}
    </div>
  )
}

function AgentIntegrationTab({ agent }: { agent: Agent }) {
  const code = `import { Guard } from '@axiomguard/sdk'

const guard = new Guard({
  cpUrl: 'https://api.axiomguard.com',
  apiKey: 'YOUR_API_KEY',
  agentId: '${agent.id}',
})

const result = await guard.check({
  tool: 'read_file',
  args: { path: '/tmp/data.txt' }
})`

  return (
    <div className="space-y-4">
      <Card title="SDK Integration">
        <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg text-sm overflow-auto">{code}</pre>
      </Card>
      <div>
        <label className="block text-sm font-medium text-slate-700 mb-1">Agent ID</label>
        <code className="block bg-slate-100 p-3 rounded text-sm font-mono">{agent.id}</code>
      </div>
    </div>
  )
}
