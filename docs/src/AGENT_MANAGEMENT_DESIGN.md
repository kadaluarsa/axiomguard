# Agent Management & Event Observation Design

## 1. Agent Integration Flow

### Concept: "Agent" as Integration Endpoint

An **Agent** represents a tenant's integration endpoint (MCP client, proxy, or direct API consumer).

```
Tenant → Creates Agents → Assigns Rules → Agent Classifies Traffic
```

### Agent Lifecycle

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Create    │────▶│  Configure  │────▶│   Deploy    │
│    Agent    │     │    Rules    │     │   API Key   │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                                │
                    ┌─────────────┐            │
                    │   Monitor   │◀───────────┘
                    │   Events    │
                    └─────────────┘
```

### Data Model

```rust
struct Agent {
    id: String,                    // ag_xxx
    tenant_id: String,
    name: String,                  // "Production MCP Client"
    description: String,
    agent_type: AgentType,         // McpClient, Proxy, Direct
    status: AgentStatus,           // Active, Paused, Disabled
    
    // Rule assignment
    assigned_rules: Vec<String>,   // Rule IDs
    rule_mode: RuleMode,           // AllRules, SelectedOnly, ExcludeSelected
    
    // Configuration
    routing_mode: RoutingMode,     // Sequential, Smart, etc.
    pii_redaction: bool,
    
    // Integration
    api_key_id: String,            // Associated API key
    webhook_url: Option<String>,
    
    // Metadata
    created_at: DateTime,
    last_seen_at: Option<DateTime>,
    request_count: u64,
    version: Option<String>,       // Agent SDK version
}

enum AgentType {
    McpClient,      // Model Context Protocol client
    Proxy,          // HTTP/WebSocket proxy
    DirectApi,      // Direct REST API consumer
    Webhook,        // Webhook receiver
}

enum RuleMode {
    AllRules,           // Use all tenant rules
    SelectedOnly,       // Only use assigned_rules
    ExcludeSelected,    // Use all except assigned_rules
}
```

### API Endpoints

```
# Agent Management
GET    /api/v1/agents                    # List agents
POST   /api/v1/agents                    # Create agent
GET    /api/v1/agents/:id                # Get agent details
PUT    /api/v1/agents/:id                # Update agent
DELETE /api/v1/agents/:id                # Delete agent
POST   /api/v1/agents/:id/pause          # Pause agent
POST   /api/v1/agents/:id/resume         # Resume agent

# Rule Assignment
GET    /api/v1/agents/:id/rules          # Get assigned rules
POST   /api/v1/agents/:id/rules          # Assign rules
DELETE /api/v1/agents/:id/rules/:rule_id # Unassign rule
PUT    /api/v1/agents/:id/rule-mode      # Update rule mode

# Agent Statistics
GET    /api/v1/agents/:id/stats          # Agent statistics
GET    /api/v1/agents/:id/events         # Agent-specific events
```

### Integration Flow for Tenants

1. **Create Agent** → Tenant creates an agent (e.g., "Production MCP")
2. **Configure Rules** → Assign specific rules or use all rules
3. **Get API Key** → Generate API key linked to agent
4. **Deploy** → Install agent SDK/config with API key
5. **Monitor** → View real-time events and statistics

## 2. Event Observation

### Two-Mode Observation System

#### Mode A: Historic Events with Histogram

```
┌─────────────────────────────────────────────────────────────┐
│  Time Range: [15m] [30m] [1h] [6h] [24h] [7d] [Custom]     │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  ▲                                                  │   │
│  │  │    ██                                            │   │
│  │  │    ██  ████                                      │   │
│  │  │   ████ ████ ████        ████                    │   │
│  │  │   ████ ████ ████ ████   ████ ████               │   │
│  │  │  █████ ████ ████ ████  █████ ████ ████          │   │
│  │  └──┴────┴────┴────┴────┴────┴────┴────▶          │   │
│  │     14:00   15:00   16:00   17:00   18:00          │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
├─────────────────────────────────────────────────────────────┤
│  Events (2,847 total)                    [Export] [Stream] │
│  ─────────────────────────────────────────────────────────  │
│  Time      Agent       Action  Rule           Severity Path │
│  18:23:45  prod-mcp    BLOCK   sql-injection  HIGH     /api │
│  18:23:12  prod-mcp    ALLOW   -              -        /health│
│  ...                                                        │
└─────────────────────────────────────────────────────────────┘
```

**Time Buckets:**
- 15m: 15-second buckets (60 points)
- 30m: 30-second buckets (60 points)
- 1h: 1-minute buckets (60 points)
- 6h: 5-minute buckets (72 points)
- 24h: 15-minute buckets (96 points)
- 7d: 1-hour buckets (168 points)

**Histogram API:**
```
GET /api/v1/events/histogram?from=2024-01-01T00:00:00Z&to=2024-01-01T23:59:59Z&bucket=1m

Response:
{
  "buckets": [
    {"timestamp": "2024-01-01T00:00:00Z", "total": 150, "blocked": 12, "allowed": 138},
    ...
  ],
  "total_events": 8472,
  "time_range": {"from": "...", "to": "..."}
}
```

#### Mode B: Real-time Event Stream (Axiom-style)

```
┌─────────────────────────────────────────────────────────────┐
│  🔴 LIVE    Events: 1,234/sec    Latency: 45ms             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─ Filters ──────────────────────────────────────────┐    │
│  │ Agent: [All ▼]  Action: [Blocked ▼]  Search: [___] │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                             │
│  ┌─ Live Event Stream ─────────────────────────────────┐   │
│  │                                                     │   │
│  │  ▓ 18:24:32.452  prod-mcp     BLOCK  sql-injection  │   │
│  │    POST /api/query  23ms  trace:abc123              │   │
│  │                                                     │   │
│  │  ░ 18:24:32.189  prod-mcp     ALLOW  -              │   │
│  │    GET /health  5ms  trace:def456                   │   │
│  │                                                     │   │
│  │  ▓ 18:24:31.847  staging-mcp  FLAG   pii-detected   │   │
│  │    POST /api/users  67ms  trace:ghi789              │   │
│  │                                                     │   │
│  │           ... auto-scroll new events ...            │   │
│  │                                                     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  [⏸ Pause]  [📊 View in Histogram Mode]  [⚡ Auto-refresh] │
└─────────────────────────────────────────────────────────────┘
```

**Real-time Features:**
- WebSocket streaming (`ws://api/ws/events?agent_id=xxx`)
- Auto-scroll with pause on hover
- Filter in real-time (client-side)
- Click event to view details
- Export current view

### Event Detail Panel

```
┌─ Event Details ─────────────────────────┐
│ Time:     2024-01-15 18:24:32.452 UTC   │
│ Agent:    prod-mcp                      │
│ Action:   🔴 BLOCK                      │
│ Rule:     sql-injection                 │
│ Severity: HIGH                          │
├─────────────────────────────────────────┤
│ REQUEST                                 │
│ POST /api/query HTTP/1.1                │
│ Host: api.example.com                   │
│ Content-Type: application/json          │
│                                         │
│ {"query": "SELECT * FROM users WHERE... │
│ -- [REDACTED-PII]                       │
├─────────────────────────────────────────┤
│ CLASSIFICATION                          │
│ Mode:     Sequential                    │
│ Rules:    sql-injection (matched)       │
│ AI:       Not consulted                 │
│ Latency:  23ms                          │
├─────────────────────────────────────────┤
│ TRACE                                   │
│ trace-id: abc123-def456-ghi789          │
│ [View in Trace Explorer]                │
└─────────────────────────────────────────┘
```

## 3. API Key Rotation

### Key Lifecycle

```
┌─────────┐    ┌─────────┐    ┌─────────┐    ┌─────────┐
│ Created │───▶│ Active  │───▶│ Expiring│───▶│ Expired │
└─────────┘    └────┬────┘    └────┬────┘    └─────────┘
                    │              │
                    ▼              ▼
               ┌─────────┐   ┌─────────┐
               │Rotated  │   │Revoked  │
               │(old key)│   │         │
               └─────────┘   └─────────┘
```

### Rotation Flow

```
1. Tenant initiates rotation
   POST /api/v1/api-keys/:id/rotate
   
2. System creates new key
   - New key is active immediately
   - Old key remains valid for grace period (default: 24h)
   - Both keys show in list
   
3. Tenant updates agents
   - Gradually roll out new key
   
4. Old key expires/revoked
   - After grace period or manual revoke
```

### Enhanced API Key Model

```typescript
interface ApiKey {
  id: string
  name: string
  keyPrefix: string
  
  // Status
  status: 'active' | 'rotating' | 'expiring' | 'expired' | 'revoked'
  
  // Rotation
  rotatedFromId?: string        // Previous key (if rotated)
  rotatedToId?: string          // New key (if rotated)
  gracePeriodEndsAt?: string    // When old key expires
  
  // Lifecycle
  createdAt: string
  expiresAt?: string
  lastUsedAt?: string
  revokedAt?: string
  
  // Security
  permissions: string[]
  ipAllowlist?: string[]
  
  // Association
  agentId?: string              // Linked agent
}

// Rotation Request
interface RotateKeyRequest {
  gracePeriodHours: number      // 1-168 hours (default: 24)
  revokeOldImmediately: boolean // Default: false
}

// Rotation Response
interface RotateKeyResponse {
  oldKey: ApiKey                // Updated old key
  newKey: ApiKey                // Brand new key
  fullKey: string               // Full key (shown once)
  gracePeriodEndsAt: string
}
```

### API Endpoints

```
POST   /api/v1/api-keys/:id/rotate           # Rotate key
POST   /api/v1/api-keys/:id/revoke           # Revoke immediately
GET    /api/v1/api-keys/:id/rotation-chain   # View rotation history
```

### UI Features

```
┌─ API Keys ──────────────────────────────┐
│                                         │
│  🔑 production-mcp                      │
│     Prefix: ag_xxx...9abc    ● Active   │
│     Agent: prod-mcp                     │
│     Last used: 2 min ago                │
│     [Rotate] [Revoke] [Edit]            │
│                                         │
│  🔑 production-mcp (old)                │
│     Prefix: ag_xxx...xyz    ⏳ Rotating │
│     Expires: 22 hours (grace period)    │
│     [Revoke Now] [Extend Grace]         │
│                                         │
└─────────────────────────────────────────┘
```

## Implementation Checklist

### Backend (Rust)
- [ ] Add Agent entity to database
- [ ] Create Agent CRUD endpoints
- [ ] Implement rule assignment logic
- [ ] Add event histogram aggregation
- [ ] Enhance WebSocket for filtered streaming
- [ ] Add API key rotation endpoints
- [ ] Implement grace period logic

### Frontend (React)
- [ ] Create Agents management page
- [ ] Build rule assignment UI
- [ ] Enhance Events with histogram view
- [ ] Create real-time event stream view
- [ ] Add API key rotation UI
- [ ] Add rotation chain viewer
