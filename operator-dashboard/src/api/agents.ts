import { apiClient } from './client'
import type { Agent, AgentRuleBinding } from '../types'

export async function getAgents(): Promise<Agent[]> {
  return apiClient.get<Agent[]>('/admin/agents')
}

export async function getAgent(id: string): Promise<Agent> {
  return apiClient.get<Agent>(`/admin/agents/${id}`)
}

export async function createAgent(agent: Omit<Agent, 'createdAt' | 'updatedAt'>): Promise<Agent> {
  return apiClient.post<Agent>('/admin/agents', agent)
}

export async function updateAgent(id: string, agent: Partial<Agent>): Promise<Agent> {
  return apiClient.put<Agent>(`/admin/agents/${id}`, agent)
}

export async function deleteAgent(id: string): Promise<{ deleted: string }> {
  return apiClient.delete<{ deleted: string }>(`/admin/agents/${id}`)
}

export async function getAgentRules(agentId: string): Promise<AgentRuleBinding[]> {
  return apiClient.get<AgentRuleBinding[]>(`/admin/agents/${agentId}/rules`)
}

export async function assignAgentRule(agentId: string, ruleId: string, priorityOverride?: number): Promise<{ assigned: string }> {
  return apiClient.post<{ assigned: string }>(`/admin/agents/${agentId}/rules`, { rule_id: ruleId, priority_override: priorityOverride })
}

export async function unassignAgentRule(agentId: string, ruleId: string): Promise<{ unassigned: string }> {
  return apiClient.delete<{ unassigned: string }>(`/admin/agents/${agentId}/rules/${ruleId}`)
}
