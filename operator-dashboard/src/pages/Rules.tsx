import React, { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Edit2, Trash2 } from 'lucide-react'
import { Card, Button, Badge, Modal, Input, Skeleton, EmptyState } from '../components/ui'
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from '../components/ui/Table'
import { Tabs, TabList, Tab, TabPanel } from '../components/ui/Tabs'
import { getRules, createRule, updateRule, deleteRule, RULE_TEMPLATES } from '../api/rules'
import type { Rule } from '../types'
import * as jsonLogic from 'json-logic-js'

export default function Rules() {
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false)
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const queryClient = useQueryClient()

  const { data: rules, isLoading } = useQuery({ queryKey: ['rules'], queryFn: getRules })

  const createMutation = useMutation({
    mutationFn: createRule,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      setIsCreateModalOpen(false)
    },
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, rule }: { id: string; rule: Partial<Rule> }) => updateRule(id, rule as Rule),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteRule,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['rules'] }),
  })

  const toggleActive = (rule: Rule) => {
    updateMutation.mutate({ id: rule.id, rule: { isActive: !rule.isActive } })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Security Rules</h1>
          <p className="text-slate-500">Manage JSONLogic rules for agent guardrails</p>
        </div>
        <Button onClick={() => setIsCreateModalOpen(true)}>
          <Plus className="h-4 w-4 mr-2" />
          Create Rule
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <Skeleton className="h-96" />
        ) : rules?.length ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Priority</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Version</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>
                    <div>
                      <p className="font-medium text-slate-900">{rule.name}</p>
                      <p className="text-xs text-slate-500 truncate max-w-xs">{rule.description}</p>
                    </div>
                  </TableCell>
                  <TableCell>{rule.priority}</TableCell>
                  <TableCell>
                    <Badge variant={rule.decision === 'Block' ? 'destructive' : rule.decision === 'Allow' ? 'default' : 'secondary'}>
                      {rule.decision}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <button
                      onClick={() => toggleActive(rule)}
                      className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
                        rule.isActive ? 'bg-green-100 text-green-800' : 'bg-slate-100 text-slate-600'
                      }`}
                    >
                      {rule.isActive ? 'Active' : 'Disabled'}
                    </button>
                  </TableCell>
                  <TableCell>v{rule.version}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="ghost" size="sm" onClick={() => setEditingRule(rule)}>
                        <Edit2 className="h-4 w-4" />
                      </Button>
                      <Button variant="ghost" size="sm" onClick={() => confirm(`Delete ${rule.name}?`) && deleteMutation.mutate(rule.id)}>
                        <Trash2 className="h-4 w-4 text-red-600" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : (
          <EmptyState
            title="No rules yet"
            description="Create a rule to define guardrail behavior"
            icon="shield"
            action={
              <Button onClick={() => setIsCreateModalOpen(true)}>
                <Plus className="h-4 w-4 mr-2" />
                Create Rule
              </Button>
            }
          />
        )}
      </Card>

      <RuleModal
        isOpen={isCreateModalOpen || !!editingRule}
        onClose={() => {
          setIsCreateModalOpen(false)
          setEditingRule(null)
        }}
        rule={editingRule}
        onSave={(rule) => {
          if (editingRule) {
            updateMutation.mutate({ id: editingRule.id, rule })
            setEditingRule(null)
          } else {
            createMutation.mutate(rule as Rule)
          }
        }}
        isLoading={createMutation.isPending || updateMutation.isPending}
      />
    </div>
  )
}

function RuleModal({
  isOpen,
  onClose,
  rule,
  onSave,
  isLoading,
}: {
  isOpen: boolean
  onClose: () => void
  rule: Rule | null
  onSave: (rule: Partial<Rule>) => void
  isLoading: boolean
}) {
  const [form, setForm] = useState<Partial<Rule>>({
    name: '',
    description: '',
    logic: {},
    decision: 'Block',
    priority: 100,
    isActive: true,
    tenantId: 'default',
  })
  const [logicText, setLogicText] = useState('{}')
  const [testInput, setTestInput] = useState('{}')
  const [testResult, setTestResult] = useState<unknown>(null)
  const [, setActiveTab] = useState('builder')

  // Reset form when modal opens
  React.useEffect(() => {
    if (!isOpen) return
    if (rule) {
      setForm(rule)
      setLogicText(JSON.stringify(rule.logic, null, 2))
    } else {
      setForm({
        name: '',
        description: '',
        logic: {},
        decision: 'Block',
        priority: 100,
        isActive: true,
        tenantId: 'default',
      })
      setLogicText('{}')
    }
    setTestInput('{}')
    setTestResult(null)
  }, [isOpen, rule])

  const isEditing = !!rule

  const handleSave = () => {
    try {
      const logic = JSON.parse(logicText)
      onSave({ ...form, logic })
    } catch {
      // ignore invalid JSON
    }
  }

  const runTest = () => {
    try {
      const logicObj = JSON.parse(logicText)
      const inputObj = JSON.parse(testInput)
      const result = jsonLogic.apply(logicObj, inputObj)
      setTestResult(result)
    } catch (e) {
      setTestResult(`Error: ${e}`)
    }
  }

  const loadTemplate = (template: Partial<Rule>) => {
    setForm((f) => ({ ...f, ...template }))
    setLogicText(JSON.stringify(template.logic, null, 2))
  }

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      title={isEditing ? 'Edit Rule' : 'Create Rule'}
      size="xl"
      footer={
        <>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={handleSave} isLoading={isLoading}>Save Rule</Button>
        </>
      }
    >
      <Tabs defaultTab="builder" onValueChange={setActiveTab}>
        <TabList>
          <Tab value="builder">Builder</Tab>
          <Tab value="test">Test Rule</Tab>
          <Tab value="templates">Templates</Tab>
        </TabList>

        <TabPanel value="builder">
          <div className="space-y-4">
            <Input
              label="Name"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
            <Input
              label="Description"
              value={form.description}
              onChange={(e) => setForm((f) => ({ ...f, description: e.target.value }))}
            />
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Decision</label>
                <select
                  value={form.decision}
                  onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setForm((f) => ({ ...f, decision: e.target.value as any }))}
                  className="w-full px-3 py-2 border border-slate-300 rounded-md"
                >
                  <option value="Allow">Allow</option>
                  <option value="Block">Block</option>
                  <option value="Flag">Flag</option>
                  <option value="Handover">Handover</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Priority</label>
                <input
                  type="number"
                  value={form.priority}
                  onChange={(e) => setForm((f) => ({ ...f, priority: parseInt(e.target.value) }))}
                  className="w-full px-3 py-2 border border-slate-300 rounded-md"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">JSONLogic</label>
              <textarea
                value={logicText}
                onChange={(e) => setLogicText(e.target.value)}
                rows={8}
                className="w-full px-3 py-2 border border-slate-300 rounded-md font-mono text-sm"
              />
            </div>
          </div>
        </TabPanel>

        <TabPanel value="test">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Test Input (JSON)</label>
              <textarea
                value={testInput}
                onChange={(e) => setTestInput(e.target.value)}
                rows={6}
                className="w-full px-3 py-2 border border-slate-300 rounded-md font-mono text-sm"
              />
            </div>
            <Button onClick={runTest} variant="outline">Run Test</Button>
            {testResult !== null && (
              <div className="p-3 bg-slate-100 rounded-md font-mono text-sm">
                Result: {JSON.stringify(testResult)}
              </div>
            )}
          </div>
        </TabPanel>

        <TabPanel value="templates">
          <div className="space-y-3">
            {RULE_TEMPLATES.map((t) => (
              <div key={t.id} className="p-4 border border-slate-200 rounded-lg hover:bg-slate-50">
                <div className="flex items-start justify-between">
                  <div>
                    <p className="font-medium">{t.name}</p>
                    <p className="text-sm text-slate-500">{t.description}</p>
                    <Badge variant="secondary" className="mt-2">{t.category}</Badge>
                  </div>
                  <Button size="sm" onClick={() => loadTemplate(t.template)}>Use Template</Button>
                </div>
              </div>
            ))}
          </div>
        </TabPanel>
      </Tabs>
    </Modal>
  )
}
