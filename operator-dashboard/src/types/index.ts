// =============================================================================
// v4 Control Plane Types
// =============================================================================

export type ToolPermission =
  | { type: 'Allow' }
  | { type: 'Deny' }
  | { type: 'Restrict'; allowedArgs: string[] }

export interface Agent {
  id: string
  tenantId: string
  name: string
  toolAllowlist: Record<string, ToolPermission>
  riskThreshold: number
  quotaMaxDaily: number
  quotaMaxBurst: number
  createdAt: string
  updatedAt: string
}

export interface AgentRuleBinding {
  agentId: string
  ruleId: string
  priorityOverride?: number
}

export interface Rule {
  id: string
  tenantId: string
  name: string
  description: string
  logic: Record<string, unknown>
  decision: 'Allow' | 'Block' | 'Flag' | 'Handover'
  priority: number
  isActive: boolean
  version: number
}

export interface RuleTemplate {
  id: string
  name: string
  description: string
  category: string
  defaultAction: string
  template: Omit<Rule, 'id' | 'tenantId' | 'version'>
}

// =============================================================================
// API Key Types
// =============================================================================

export type ApiKeyStatus = 'active' | 'rotating' | 'expiring' | 'expired' | 'revoked'

export interface ApiKey {
  id: string
  name: string
  keyPrefix: string
  status: ApiKeyStatus
  rotatedFromId?: string
  rotatedToId?: string
  gracePeriodEndsAt?: string
  createdAt: string
  expiresAt?: string
  lastUsedAt?: string
  revokedAt?: string
  permissions: string[]
  agentId?: string
  agentName?: string
}

export interface CreateApiKeyRequest {
  name: string
  agentId?: string
  permissions: string[]
  expiresInDays?: number
}

export interface RotateKeyRequest {
  gracePeriodHours: number
  revokeOldImmediately: boolean
}

// =============================================================================
// Analytics Types
// =============================================================================

export interface AggregateStats {
  totalCalls: number
  allowCount: number
  blockCount: number
  flagCount: number
  avgLatencyMs: number
}

export interface AgentAnalytics {
  agentId: string
  name: string
  totalCalls: number
  allowCount: number
  blockCount: number
  flagCount: number
  avgLatencyMs: number
}

export interface AnalyticsResponse {
  aggregate: AggregateStats
  perAgent: AgentAnalytics[]
  cacheHitRate: number
}

// =============================================================================
// Audit / Event Types
// =============================================================================

export type EventAction = 'blocked' | 'allowed' | 'flagged' | 'modified'
export type EventSeverity = 'critical' | 'high' | 'medium' | 'low'

export interface SecurityEvent {
  id: string
  timestamp: string
  action: EventAction
  severity: EventSeverity
  ruleId?: string
  ruleName?: string
  agentId?: string
  agentName?: string
  clientIp?: string
  userAgent?: string
  path?: string
  method?: string
  latencyMs: number
  details: EventDetails
  traceId: string
  request?: RequestDetails
  response?: ResponseDetails
}

export interface AuditEvent {
  id: string
  tenantId: string
  eventType: string
  source: string
  sessionId?: string
  decisionType?: string
  confidence?: number
  processingTimeMs?: number
  data: Record<string, unknown>
  timestamp: string
  createdAt: string
}

export interface RequestDetails {
  method: string
  path: string
  headers: Record<string, string>
  body?: string
  queryParams?: Record<string, string>
}

export interface ResponseDetails {
  statusCode: number
  headers: Record<string, string>
  body?: string
}

export interface EventDetails {
  triggeredRule?: string
  piiDetected?: PiiFinding[]
  quotaExceeded?: boolean
  modificationSummary?: string
  aiAnalysis?: AiAnalysisResult
}

export interface PiiFinding {
  piiType: string
  confidence: number
  position: [number, number]
}

export interface AiAnalysisResult {
  classification: string
  confidence: number
  explanation: string
}

export interface HistogramBucket {
  timestamp: string
  total: number
  blocked: number
  allowed: number
  flagged: number
  modified: number
}

export interface EventHistogram {
  buckets: HistogramBucket[]
  totalEvents: number
  timeRange: {
    from: string
    to: string
  }
  bucketSize: string
}

// =============================================================================
// Session Types
// =============================================================================

export interface Session {
  sessionId: string
  agentId: string
  toolCallCount: number
  riskScore: number
  createdAt: string
  lastActive: string
}

export interface SessionTimelineItem {
  timestamp: string
  tool: string
  decision: EventAction
  reason: string
}

// =============================================================================
// Bypass Alert Types
// =============================================================================

export interface BypassAlert {
  id: string
  tenantId: string
  agentId: string
  toolName: string
  reason: string
  timestamp: string
}

// =============================================================================
// Tenant & Settings Types
// =============================================================================

export interface Tenant {
  id: string
  name: string
  tier: 'free' | 'pro' | 'enterprise'
  createdAt: string
  settings: TenantSettings
}

export interface TenantSettings {
  webhookUrl?: string
  webhookEnabled: boolean
  webhookSecret?: string
}

// =============================================================================
// Common Response Types
// =============================================================================

export interface ApiResponse<T> {
  success: boolean
  data: T
  error?: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
  hasMore: boolean
}

export interface AuditListResponse {
  events: AuditEvent[]
  total: number
  page: number
  pageSize: number
}

export interface FilterParams {
  startDate?: string
  endDate?: string
  action?: EventAction
  severity?: EventSeverity
  search?: string
  agentId?: string
  ruleId?: string
  page?: number
  pageSize?: number
}

export interface RealtimeEventFilter {
  agentId?: string
  action?: EventAction
  severity?: EventSeverity
  search?: string
}
