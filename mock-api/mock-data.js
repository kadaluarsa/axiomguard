// Generate realistic mock data for AxiomGuard
export function generateMockData() {
  const now = new Date();
  
  // Agents
  const agents = [
    {
      id: 'ag_prod_mcp_001',
      tenantId: 'tenant_123',
      name: 'Production MCP Client',
      description: 'Main production MCP client for API traffic',
      agentType: 'mcp_client',
      status: 'active',
      assignedRules: ['rule_1', 'rule_2', 'rule_3'],
      ruleMode: 'selected_only',
      routingMode: 'sequential',
      piiRedaction: true,
      apiKeyId: 'key_001',
      apiKeyPrefix: 'ag_prod_9x',
      createdAt: new Date(now - 86400000 * 30).toISOString(),
      lastSeenAt: new Date(now - 60000).toISOString(),
      requestCount: 15234,
      version: '1.2.3',
      tags: ['production', 'mcp', 'critical'],
    },
    {
      id: 'ag_staging_proxy_001',
      tenantId: 'tenant_123',
      name: 'Staging Proxy',
      description: 'Staging environment HTTP proxy',
      agentType: 'proxy',
      status: 'active',
      assignedRules: [],
      ruleMode: 'all_rules',
      routingMode: 'smart',
      piiRedaction: true,
      apiKeyId: 'key_002',
      apiKeyPrefix: 'ag_stag_7k',
      createdAt: new Date(now - 86400000 * 15).toISOString(),
      lastSeenAt: new Date(now - 300000).toISOString(),
      requestCount: 3456,
      version: '1.2.0',
      tags: ['staging', 'proxy'],
    },
    {
      id: 'ag_dev_direct_001',
      tenantId: 'tenant_123',
      name: 'Development Direct API',
      description: 'Development direct API integration',
      agentType: 'direct_api',
      status: 'paused',
      assignedRules: ['rule_1'],
      ruleMode: 'selected_only',
      routingMode: 'rules_only',
      piiRedaction: false,
      apiKeyId: 'key_003',
      apiKeyPrefix: 'ag_dev_3m',
      createdAt: new Date(now - 86400000 * 7).toISOString(),
      lastSeenAt: new Date(now - 86400000).toISOString(),
      requestCount: 892,
      version: '1.1.0',
      tags: ['development'],
    },
  ];

  // Rules
  const rules = [
    {
      id: 'rule_1',
      name: 'SQL Injection Detection',
      description: 'Detects and blocks common SQL injection patterns',
      enabled: true,
      priority: 100,
      action: 'block',
      operator: 'regex',
      conditions: [{ field: 'content', operator: 'matches', value: '(union|select|insert|update|delete|drop).*' }],
      createdAt: new Date(now - 86400000 * 60).toISOString(),
      updatedAt: new Date(now - 86400000 * 10).toISOString(),
      hitCount: 1523,
      lastHit: new Date(now - 300000).toISOString(),
    },
    {
      id: 'rule_2',
      name: 'XSS Prevention',
      description: 'Prevents cross-site scripting attacks',
      enabled: true,
      priority: 90,
      action: 'block',
      operator: 'contains',
      conditions: [{ field: 'content', operator: 'contains', value: '<script>' }],
      createdAt: new Date(now - 86400000 * 55).toISOString(),
      updatedAt: new Date(now - 86400000 * 5).toISOString(),
      hitCount: 892,
      lastHit: new Date(now - 600000).toISOString(),
    },
    {
      id: 'rule_3',
      name: 'Rate Limit',
      description: 'Enforces rate limiting per IP',
      enabled: true,
      priority: 80,
      action: 'block',
      operator: 'jsonlogic',
      conditions: [{ field: 'rate', operator: 'exceeds', value: 100 }],
      createdAt: new Date(now - 86400000 * 50).toISOString(),
      updatedAt: new Date(now - 86400000 * 20).toISOString(),
      hitCount: 2341,
      lastHit: new Date(now - 120000).toISOString(),
    },
    {
      id: 'rule_4',
      name: 'PII Detection',
      description: 'Flags requests containing PII',
      enabled: true,
      priority: 70,
      action: 'flag',
      operator: 'regex',
      conditions: [{ field: 'content', operator: 'matches', value: '\\b\\d{3}-\\d{2}-\\d{4}\\b' }],
      createdAt: new Date(now - 86400000 * 40).toISOString(),
      updatedAt: new Date(now - 86400000 * 2).toISOString(),
      hitCount: 456,
      lastHit: new Date(now - 900000).toISOString(),
    },
    {
      id: 'rule_5',
      name: 'Auth Check',
      description: 'Validates authentication tokens',
      enabled: false,
      priority: 95,
      action: 'block',
      operator: 'jsonlogic',
      conditions: [],
      createdAt: new Date(now - 86400000 * 30).toISOString(),
      updatedAt: new Date(now - 86400000).toISOString(),
      hitCount: 0,
      lastHit: undefined,
    },
  ];

  // Rule Templates
  const ruleTemplates = [
    {
      id: 'template_1',
      name: 'SQL Injection Protection',
      description: 'Standard SQL injection protection rules',
      category: 'security',
      defaultAction: 'block',
      template: {
        name: 'SQL Injection Protection',
        description: 'Blocks SQL injection attempts',
        enabled: true,
        priority: 100,
        action: 'block',
        operator: 'regex',
        conditions: [],
      },
    },
    {
      id: 'template_2',
      name: 'XSS Protection',
      description: 'Cross-site scripting protection',
      category: 'security',
      defaultAction: 'block',
      template: {
        name: 'XSS Protection',
        description: 'Prevents XSS attacks',
        enabled: true,
        priority: 90,
        action: 'block',
        operator: 'contains',
        conditions: [],
      },
    },
    {
      id: 'template_3',
      name: 'Rate Limiting',
      description: 'Basic rate limiting configuration',
      category: 'performance',
      defaultAction: 'block',
      template: {
        name: 'Rate Limit',
        description: 'Limits request rate',
        enabled: true,
        priority: 80,
        action: 'block',
        operator: 'jsonlogic',
        conditions: [],
      },
    },
  ];

  // API Keys
  const apiKeys = [
    {
      id: 'key_001',
      name: 'Production API Key',
      keyPrefix: 'ag_prod_9x7k2m',
      status: 'active',
      createdAt: new Date(now - 86400000 * 30).toISOString(),
      lastUsedAt: new Date(now - 60000).toISOString(),
      permissions: ['read:events', 'write:rules', 'read:stats', 'read:agents', 'write:agents'],
      agentId: 'ag_prod_mcp_001',
      agentName: 'Production MCP Client',
      enabled: true,
    },
    {
      id: 'key_002',
      name: 'Staging API Key',
      keyPrefix: 'ag_stag_7k3p9n',
      status: 'active',
      createdAt: new Date(now - 86400000 * 15).toISOString(),
      lastUsedAt: new Date(now - 300000).toISOString(),
      permissions: ['read:events', 'read:stats', 'read:agents'],
      agentId: 'ag_staging_proxy_001',
      agentName: 'Staging Proxy',
      enabled: true,
    },
    {
      id: 'key_003',
      name: 'Development API Key',
      keyPrefix: 'ag_dev_3m8q1r',
      status: 'rotating',
      rotatedToId: 'key_004',
      gracePeriodEndsAt: new Date(now + 86400000 * 2).toISOString(),
      createdAt: new Date(now - 86400000 * 7).toISOString(),
      lastUsedAt: new Date(now - 86400000).toISOString(),
      permissions: ['read:events', 'read:stats'],
      agentId: 'ag_dev_direct_001',
      agentName: 'Development Direct API',
      enabled: true,
    },
    {
      id: 'key_004',
      name: 'Development API Key (New)',
      keyPrefix: 'ag_dev_9x2k7m',
      status: 'active',
      rotatedFromId: 'key_003',
      createdAt: new Date(now - 3600000).toISOString(),
      lastUsedAt: new Date(now - 1800000).toISOString(),
      permissions: ['read:events', 'read:stats'],
      agentId: 'ag_dev_direct_001',
      agentName: 'Development Direct API',
      enabled: true,
    },
    {
      id: 'key_005',
      name: 'Old Production Key',
      keyPrefix: 'ag_old_2m9p5n',
      status: 'revoked',
      rotatedToId: 'key_001',
      revokedAt: new Date(now - 86400000 * 25).toISOString(),
      createdAt: new Date(now - 86400000 * 60).toISOString(),
      lastUsedAt: new Date(now - 86400000 * 26).toISOString(),
      permissions: ['read:events'],
      enabled: false,
    },
  ];

  // Generate Events
  const events = [];
  const actions = ['blocked', 'allowed', 'flagged'];
  const severities = ['critical', 'high', 'medium', 'low'];
  const paths = ['/api/users', '/api/query', '/api/data', '/health', '/api/login', '/api/payments'];
  const methods = ['GET', 'POST', 'PUT', 'DELETE'];
  
  for (let i = 0; i < 150; i++) {
    const agent = agents[Math.floor(Math.random() * agents.length)];
    const action = actions[Math.floor(Math.random() * actions.length)];
    const timestamp = new Date(now - Math.random() * 86400000 * 7);
    
    events.push({
      id: `evt_${timestamp.getTime()}_${i}`,
      timestamp: timestamp.toISOString(),
      action,
      severity: severities[Math.floor(Math.random() * severities.length)],
      ruleId: `rule_${Math.floor(Math.random() * 5) + 1}`,
      ruleName: rules[Math.floor(Math.random() * rules.length)].name,
      agentId: agent.id,
      agentName: agent.name,
      clientIp: `192.168.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
      path: paths[Math.floor(Math.random() * paths.length)],
      method: methods[Math.floor(Math.random() * methods.length)],
      latencyMs: Math.floor(Math.random() * 100) + 5,
      traceId: `trace_${Math.random().toString(36).substring(2, 18)}`,
      details: {
        triggeredRule: action !== 'allowed' ? rules[Math.floor(Math.random() * rules.length)].name : undefined,
        piiDetected: Math.random() > 0.8 ? [
          { piiType: 'ssn', confidence: 0.95, position: [10, 21] },
        ] : undefined,
        aiAnalysis: Math.random() > 0.7 ? {
          classification: 'suspicious_content',
          confidence: 0.82,
          explanation: 'Content patterns match known attack signatures',
        } : undefined,
      },
      request: {
        method: methods[Math.floor(Math.random() * methods.length)],
        path: paths[Math.floor(Math.random() * paths.length)],
        headers: {
          'content-type': 'application/json',
          'authorization': 'Bearer ***',
        },
        body: JSON.stringify({ query: 'SELECT * FROM users WHERE id = 1' }),
      },
    });
  }

  // Sort events by timestamp desc
  events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  // Dashboard Stats
  const dashboardStats = {
    totalRequests24h: 45234,
    blockedRequests24h: 5234,
    avgLatencyMs: 23.5,
    activeRules: 4,
    topThreats: [
      { ruleName: 'SQL Injection Detection', count: 1523, trend: 'up' },
      { ruleName: 'Rate Limit', count: 2341, trend: 'stable' },
      { ruleName: 'XSS Prevention', count: 892, trend: 'down' },
    ],
    requestTrend: Array.from({ length: 24 }, (_, i) => ({
      timestamp: new Date(now - (23 - i) * 3600000).toISOString(),
      value: Math.floor(Math.random() * 2000) + 1000,
    })),
    latencyTrend: Array.from({ length: 24 }, (_, i) => ({
      timestamp: new Date(now - (23 - i) * 3600000).toISOString(),
      value: Math.floor(Math.random() * 30) + 10,
    })),
    threatDistribution: [
      { name: 'SQL Injection', value: 1523, color: '#ef4444' },
      { name: 'XSS', value: 892, color: '#f97316' },
      { name: 'Rate Limit', value: 2341, color: '#eab308' },
      { name: 'PII Detection', value: 456, color: '#3b82f6' },
    ],
  };

  // Quota Usage
  const quotaUsage = {
    tier: 'pro',
    dailyLimit: 10000,
    monthlyLimit: 300000,
    dailyUsed: 4523,
    monthlyUsed: 125432,
    dailyResetAt: new Date(now.getTime() + 86400000).toISOString(),
    monthlyResetAt: new Date(now.getFullYear(), now.getMonth() + 1, 1).toISOString(),
    usageHistory: Array.from({ length: 30 }, (_, i) => ({
      date: new Date(now - (29 - i) * 86400000).toISOString().split('T')[0],
      requests: Math.floor(Math.random() * 8000) + 2000,
      blocked: Math.floor(Math.random() * 1000),
      latencyAvg: Math.floor(Math.random() * 30) + 10,
    })),
  };

  // Settings
  const notificationSettings = {
    emailAlerts: true,
    webhookEnabled: false,
    alertThreshold: 'immediate',
    alertOn: {
      critical: true,
      high: true,
      medium: false,
      low: false,
    },
  };

  const piiSettings = {
    enabled: true,
    types: {
      creditCard: true,
      ssn: true,
      email: true,
      phone: true,
      apiKey: true,
      password: true,
      token: true,
      ipAddress: false,
    },
    customPatterns: [
      { id: 'pattern_1', name: 'Internal ID', pattern: 'INT_[0-9]{8}', enabled: true },
    ],
  };

  return {
    agents,
    rules,
    ruleTemplates,
    apiKeys,
    events,
    dashboardStats,
    quotaUsage,
    notificationSettings,
    piiSettings,
  };
}
