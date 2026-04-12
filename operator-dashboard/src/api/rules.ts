import { apiClient } from './client'
import type { Rule, RuleTemplate } from '../types'

export async function getRules(): Promise<Rule[]> {
  return apiClient.get<Rule[]>('/admin/rules')
}

export async function getRule(id: string): Promise<Rule> {
  return apiClient.get<Rule>(`/admin/rules/${id}`)
}

export async function createRule(rule: Omit<Rule, 'id' | 'version'>): Promise<Rule> {
  return apiClient.post<Rule>('/admin/rules', rule)
}

export async function updateRule(id: string, rule: Partial<Rule>): Promise<Rule> {
  return apiClient.put<Rule>(`/admin/rules/${id}`, rule)
}

export async function deleteRule(id: string): Promise<{ deleted: string }> {
  return apiClient.delete<{ deleted: string }>(`/admin/rules/${id}`)
}

export const RULE_TEMPLATES: RuleTemplate[] = [
  {
    id: 'template_1',
    name: 'SQL Injection Protection',
    description: 'Blocks common SQL injection patterns',
    category: 'security',
    defaultAction: 'block',
    template: {
      name: 'SQL Injection Protection',
      description: 'Blocks SQL injection attempts',
      logic: { in: [{ var: 'content' }, ['union', 'select', 'insert', 'update', 'delete', 'drop']] },
      decision: 'Block',
      priority: 100,
      isActive: true,
    },
  },
  {
    id: 'template_2',
    name: 'XSS Prevention',
    description: 'Prevents cross-site scripting attacks',
    category: 'security',
    defaultAction: 'block',
    template: {
      name: 'XSS Prevention',
      description: 'Blocks XSS attempts',
      logic: { in: [{ var: 'content' }, ['<script>', 'javascript:']] },
      decision: 'Block',
      priority: 90,
      isActive: true,
    },
  },
  {
    id: 'template_3',
    name: 'Rate Limiting',
    description: 'Basic rate limiting based on call count',
    category: 'performance',
    defaultAction: 'block',
    template: {
      name: 'Rate Limit',
      description: 'Limits request rate',
      logic: { '>': [{ var: 'call_count' }, 100] },
      decision: 'Block',
      priority: 80,
      isActive: true,
    },
  },
]
