import express from 'express';
import cors from 'cors';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import { generateMockData } from './mock-data.js';
import crypto from 'crypto';

const app = express();
const server = createServer(app);
const wss = new WebSocketServer({ server, path: '/ws/events' });

app.use(cors());
app.use(express.json());

// Mock data store
const mockData = generateMockData();

// ==================== SECURITY: IN-MEMORY STORES ====================
// In production, use Redis for these

// Rate limiting store: ip -> { count, resetTime }
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX = 5; // 5 attempts per window for auth endpoints

// User store with verification status
const users = new Map();
const verificationTokens = new Map();
const VERIFICATION_GRACE_PERIOD = 24 * 60 * 60 * 1000; // 24 hours
const UNVERIFIED_CLEANUP_INTERVAL = 60 * 60 * 1000; // Clean up every hour

// Initialize demo user
const demoUserId = 'user_demo_001';
const demoTenantId = 'tenant_demo_001';
users.set(demoUserId, {
  id: demoUserId,
  email: 'demo@example.com',
  passwordHash: hashPassword('change-me-for-demo'),
  name: 'Demo User',
  tenantId: demoTenantId,
  tenantName: 'Demo Corporation',
  role: 'admin',
  verified: true,
  createdAt: new Date().toISOString(),
  lastLogin: new Date().toISOString(),
});

// ==================== SECURITY: HELPER FUNCTIONS ====================

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateVerificationToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Rate limit check
function checkRateLimit(ip, endpoint = 'default') {
  const key = `${ip}:${endpoint}`;
  const now = Date.now();
  const record = rateLimitStore.get(key);
  
  if (!record || now > record.resetTime) {
    rateLimitStore.set(key, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return { allowed: true, remaining: RATE_LIMIT_MAX - 1 };
  }
  
  if (record.count >= RATE_LIMIT_MAX) {
    return { 
      allowed: false, 
      remaining: 0,
      retryAfter: Math.ceil((record.resetTime - now) / 1000)
    };
  }
  
  record.count++;
  return { allowed: true, remaining: RATE_LIMIT_MAX - record.count };
}

// Honeypot validation - bots fill this, humans don't
function validateHoneypot(req, res, next) {
  const honeypot = req.body.website || req.body._gotcha || req.body.company;
  if (honeypot && honeypot.trim() !== '') {
    // Bot detected - silently reject but pretend success
    console.log(`🤖 Bot blocked from ${req.path} - IP: ${req.ip}`);
    return res.status(200).json({ 
      success: true, 
      message: 'Processing...',
      _bot: true // Frontend will handle this
    });
  }
  next();
}

// Cleanup unverified accounts periodically
function cleanupUnverifiedAccounts() {
  const now = Date.now();
  let cleaned = 0;
  
  for (const [userId, user] of users.entries()) {
    if (!user.verified && user.createdAt) {
      const created = new Date(user.createdAt).getTime();
      if (now - created > VERIFICATION_GRACE_PERIOD) {
        users.delete(userId);
        cleaned++;
      }
    }
  }
  
  if (cleaned > 0) {
    console.log(`🧹 Cleaned up ${cleaned} unverified accounts`);
  }
}

// Start cleanup interval
setInterval(cleanupUnverifiedAccounts, UNVERIFIED_CLEANUP_INTERVAL);

// API Response wrapper
const apiResponse = (data) => ({ success: true, data });
const apiError = (message, code = 400) => ({ success: false, error: message, code });

// ==================== SECURITY: AUTH MIDDLEWARE ====================

const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    // In a real app, verify JWT here
    // For mock, we'll trust the token format
    req.userId = 'user_demo_001'; // Simplified for mock
    req.tenantId = 'tenant_demo_001';
    req.user = users.get('user_demo_001');
  } else {
    req.tenantId = 'tenant_demo_001'; // Default for public endpoints
  }
  
  next();
};

// Verification check middleware - restricts sensitive actions
const requireVerified = (req, res, next) => {
  const user = req.user || users.get(req.userId);
  
  if (!user) {
    return res.status(401).json(apiError('Authentication required', 401));
  }
  
  if (!user.verified) {
    return res.status(403).json(apiError(
      'Email verification required. Please check your email to verify your account.', 
      403
    ));
  }
  
  next();
};

app.use(authMiddleware);

// ==================== AUTH ENDPOINTS ====================

// Register with honeypot protection and rate limiting
app.post('/api/v1/auth/register', validateHoneypot, (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  
  // Rate limit check
  const rateCheck = checkRateLimit(clientIp, 'register');
  if (!rateCheck.allowed) {
    res.set('Retry-After', rateCheck.retryAfter);
    return res.status(429).json(apiError(
      `Too many registration attempts. Please try again in ${rateCheck.retryAfter} seconds.`,
      429
    ));
  }
  
  const { email, password, name, tenantName, slug } = req.body;
  
  // Validation
  if (!email || !password || !name || !tenantName) {
    return res.status(400).json(apiError('All fields are required'));
  }
  
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json(apiError('Invalid email format'));
  }
  
  if (password.length < 8) {
    return res.status(400).json(apiError('Password must be at least 8 characters'));
  }
  
  if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
    return res.status(400).json(apiError('Password must contain uppercase, lowercase, and number'));
  }
  
  // Check if email exists
  for (const user of users.values()) {
    if (user.email === email.toLowerCase()) {
      return res.status(409).json(apiError('An account with this email already exists'));
    }
  }
  
  // Generate IDs
  const userId = `user_${Date.now()}`;
  const tenantId = `tenant_${Date.now()}`;
  
  // Create user (unverified initially)
  const verificationToken = generateVerificationToken();
  const newUser = {
    id: userId,
    email: email.toLowerCase(),
    passwordHash: hashPassword(password),
    name,
    tenantId,
    tenantName,
    role: 'admin',
    verified: false,
    verificationToken,
    createdAt: new Date().toISOString(),
    lastLogin: null,
  };
  
  users.set(userId, newUser);
  verificationTokens.set(verificationToken, userId);
  
  // Log verification link (in production, send email)
  console.log(`\n📧 VERIFICATION EMAIL for ${email}:`);
  console.log(`   Link: http://localhost:3000/verify?token=${verificationToken}`);
  console.log(`   Expires in 24 hours\n`);
  
  // Generate auth token
  const token = generateToken();
  
  res.status(201).json(apiResponse({
    token,
    user: {
      id: userId,
      email: newUser.email,
      name: newUser.name,
      role: newUser.role,
      verified: false,
    },
    tenant: {
      id: tenantId,
      name: tenantName,
      slug: slug || tenantName.toLowerCase().replace(/[^a-z0-9]+/g, '-'),
      tier: 'free',
    },
    requiresVerification: true,
    verificationEmailSent: true,
  }));
});

// Login with rate limiting
app.post('/api/v1/auth/login', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  
  // Rate limit check
  const rateCheck = checkRateLimit(clientIp, 'login');
  if (!rateCheck.allowed) {
    res.set('Retry-After', rateCheck.retryAfter);
    return res.status(429).json(apiError(
      `Too many login attempts. Please try again in ${rateCheck.retryAfter} seconds.`,
      429
    ));
  }
  
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json(apiError('Email and password are required'));
  }
  
  // Find user
  let user = null;
  for (const u of users.values()) {
    if (u.email === email.toLowerCase()) {
      user = u;
      break;
    }
  }
  
  if (!user || user.passwordHash !== hashPassword(password)) {
    return res.status(401).json(apiError('Invalid email or password', 401));
  }
  
  // Update last login
  user.lastLogin = new Date().toISOString();
  
  // Generate token
  const token = generateToken();
  
  res.json(apiResponse({
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      verified: user.verified,
    },
    tenant: {
      id: user.tenantId,
      name: user.tenantName,
      tier: 'free',
    },
    requiresVerification: !user.verified,
  }));
});

// Email verification endpoint
app.get('/api/v1/auth/verify', (req, res) => {
  const { token } = req.query;
  
  if (!token) {
    return res.status(400).json(apiError('Verification token required'));
  }
  
  const userId = verificationTokens.get(token);
  if (!userId) {
    return res.status(400).json(apiError('Invalid or expired verification token'));
  }
  
  const user = users.get(userId);
  if (!user) {
    return res.status(404).json(apiError('User not found'));
  }
  
  if (user.verified) {
    return res.json(apiResponse({ message: 'Email already verified' }));
  }
  
  // Mark as verified
  user.verified = true;
  user.verifiedAt = new Date().toISOString();
  verificationTokens.delete(token);
  
  console.log(`✅ User ${user.email} verified`);
  
  res.json(apiResponse({ message: 'Email verified successfully' }));
});

// Resend verification email
app.post('/api/v1/auth/resend-verification', (req, res) => {
  const clientIp = req.ip || req.connection.remoteAddress;
  const rateCheck = checkRateLimit(clientIp, 'resend');
  
  if (!rateCheck.allowed) {
    res.set('Retry-After', rateCheck.retryAfter);
    return res.status(429).json(apiError('Too many requests', 429));
  }
  
  const { email } = req.body;
  
  let user = null;
  for (const u of users.values()) {
    if (u.email === email?.toLowerCase()) {
      user = u;
      break;
    }
  }
  
  if (!user) {
    // Don't reveal if email exists
    return res.json(apiResponse({ message: 'If an account exists, a verification email has been sent' }));
  }
  
  if (user.verified) {
    return res.json(apiResponse({ message: 'Email already verified' }));
  }
  
  // Generate new token
  const verificationToken = generateVerificationToken();
  user.verificationToken = verificationToken;
  verificationTokens.set(verificationToken, user.id);
  
  console.log(`\n📧 RESEND VERIFICATION for ${user.email}:`);
  console.log(`   Link: http://localhost:3000/verify?token=${verificationToken}\n`);
  
  res.json(apiResponse({ message: 'Verification email sent' }));
});

// Check verification status
app.get('/api/v1/auth/me', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json(apiError('Authentication required', 401));
  }
  
  const user = req.user || users.get('user_demo_001');
  if (!user) {
    return res.status(401).json(apiError('User not found', 401));
  }
  
  res.json(apiResponse({
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      verified: user.verified,
      createdAt: user.createdAt,
    },
    tenant: {
      id: user.tenantId,
      name: user.tenantName,
      tier: 'free',
    },
  }));
});

// ==================== PROTECTED ROUTES ====================

// Apply verification requirement to sensitive endpoints
app.post('/api/v1/api-keys', requireVerified, (req, res) => {
  // ... existing code
  const newKey = {
    id: `key_${Date.now()}`,
    keyPrefix: `ag_${Math.random().toString(36).substring(2, 8)}`,
    status: 'active',
    createdAt: new Date().toISOString(),
    ...req.body,
  };
  mockData.apiKeys.push(newKey);
  res.json(apiResponse({
    apiKey: newKey,
    fullKey: `${newKey.keyPrefix}.${Math.random().toString(36).substring(2, 30)}`,
  }));
});

// ==================== DASHBOARD ====================
app.get('/api/v1/dashboard/stats', (req, res) => {
  res.json(apiResponse(mockData.dashboardStats));
});

// ==================== EVENTS ====================
app.get('/api/v1/events', (req, res) => {
  const { page = 1, page_size = 20, action, severity, agent_id, search } = req.query;
  
  let events = [...mockData.events];
  
  if (action) events = events.filter(e => e.action === action);
  if (severity) events = events.filter(e => e.severity === severity);
  if (agent_id) events = events.filter(e => e.agentId === agent_id);
  if (search) {
    const s = search.toLowerCase();
    events = events.filter(e => 
      e.path.toLowerCase().includes(s) || 
      e.ruleName.toLowerCase().includes(s)
    );
  }
  
  const total = events.length;
  const start = (page - 1) * page_size;
  const paginated = events.slice(start, start + parseInt(page_size));
  
  res.json(apiResponse({
    items: paginated,
    total,
    page: parseInt(page),
    pageSize: parseInt(page_size),
    hasMore: start + parseInt(page_size) < total,
  }));
});

app.get('/api/v1/events/:id', (req, res) => {
  const event = mockData.events.find(e => e.id === req.params.id);
  if (!event) return res.status(404).json({ success: false, error: 'Event not found' });
  res.json(apiResponse(event));
});

app.get('/api/v1/events/histogram', (req, res) => {
  const { range = '1h' } = req.query;
  
  // Generate buckets based on range
  const bucketCount = 60;
  const buckets = [];
  const now = new Date();
  
  for (let i = bucketCount - 1; i >= 0; i--) {
    const timestamp = new Date(now - i * getBucketInterval(range));
    const total = Math.floor(Math.random() * 150) + 50;
    const blocked = Math.floor(total * 0.15);
    const flagged = Math.floor(total * 0.1);
    
    buckets.push({
      timestamp: timestamp.toISOString(),
      total,
      blocked,
      allowed: total - blocked - flagged,
      flagged,
      modified: Math.floor(total * 0.05),
    });
  }
  
  res.json(apiResponse({
    buckets,
    totalEvents: buckets.reduce((sum, b) => sum + b.total, 0),
    timeRange: {
      from: buckets[0].timestamp,
      to: buckets[buckets.length - 1].timestamp,
    },
    bucketSize: getBucketSize(range),
  }));
});

function getBucketInterval(range) {
  const intervals = { '15m': 15000, '30m': 30000, '1h': 60000, '6h': 300000, '24h': 900000, '7d': 3600000 };
  return intervals[range] || 60000;
}

function getBucketSize(range) {
  const sizes = { '15m': '15s', '30m': '30s', '1h': '1m', '6h': '5m', '24h': '15m', '7d': '1h' };
  return sizes[range] || '1m';
}

// ==================== AGENTS ====================
app.get('/api/v1/agents', (req, res) => {
  res.json(apiResponse(mockData.agents));
});

app.get('/api/v1/agents/:id', (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ success: false, error: 'Agent not found' });
  res.json(apiResponse(agent));
});

app.post('/api/v1/agents', requireVerified, (req, res) => {
  const newAgent = {
    id: `ag_${Date.now()}`,
    tenantId: req.tenantId,
    createdAt: new Date().toISOString(),
    requestCount: 0,
    status: 'active',
    ...req.body,
  };
  mockData.agents.push(newAgent);
  res.json(apiResponse(newAgent));
});

app.put('/api/v1/agents/:id', requireVerified, (req, res) => {
  const index = mockData.agents.findIndex(a => a.id === req.params.id);
  if (index === -1) return res.status(404).json({ success: false, error: 'Agent not found' });
  mockData.agents[index] = { ...mockData.agents[index], ...req.body };
  res.json(apiResponse(mockData.agents[index]));
});

app.delete('/api/v1/agents/:id', requireVerified, (req, res) => {
  const index = mockData.agents.findIndex(a => a.id === req.params.id);
  if (index > -1) mockData.agents.splice(index, 1);
  res.json(apiResponse({ success: true }));
});

app.post('/api/v1/agents/:id/pause', requireVerified, (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (agent) agent.status = 'paused';
  res.json(apiResponse(agent));
});

app.post('/api/v1/agents/:id/resume', requireVerified, (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (agent) agent.status = 'active';
  res.json(apiResponse(agent));
});

app.get('/api/v1/agents/:id/rules', (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ success: false, error: 'Agent not found' });
  const rules = mockData.rules.filter(r => agent.assignedRules.includes(r.id));
  res.json(apiResponse(rules));
});

app.post('/api/v1/agents/:id/rules', requireVerified, (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ success: false, error: 'Agent not found' });
  agent.assignedRules = req.body.rule_ids || [];
  res.json(apiResponse(agent));
});

app.put('/api/v1/agents/:id/rule-mode', requireVerified, (req, res) => {
  const agent = mockData.agents.find(a => a.id === req.params.id);
  if (!agent) return res.status(404).json({ success: false, error: 'Agent not found' });
  agent.ruleMode = req.body.mode;
  res.json(apiResponse(agent));
});

app.get('/api/v1/agents/:id/stats', (req, res) => {
  res.json(apiResponse({
    agentId: req.params.id,
    period: '24h',
    totalRequests: 15234,
    blockedRequests: 2341,
    allowedRequests: 12543,
    flaggedRequests: 350,
    avgLatencyMs: 23.5,
    errorRate: 0.001,
    topRules: [
      { ruleId: 'rule_1', ruleName: 'SQL Injection Detection', count: 523 },
      { ruleId: 'rule_2', ruleName: 'XSS Prevention', count: 412 },
      { ruleId: 'rule_3', ruleName: 'Rate Limit', count: 298 },
    ],
  }));
});

// ==================== RULES ====================
app.get('/api/v1/rules', (req, res) => {
  res.json(apiResponse(mockData.rules));
});

app.post('/api/v1/rules', requireVerified, (req, res) => {
  const newRule = {
    id: `rule_${Date.now()}`,
    ...req.body,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    hitCount: 0,
  };
  mockData.rules.push(newRule);
  res.json(apiResponse(newRule));
});

app.put('/api/v1/rules/:id', requireVerified, (req, res) => {
  const index = mockData.rules.findIndex(r => r.id === req.params.id);
  if (index === -1) return res.status(404).json({ success: false, error: 'Rule not found' });
  mockData.rules[index] = { ...mockData.rules[index], ...req.body, updatedAt: new Date().toISOString() };
  res.json(apiResponse(mockData.rules[index]));
});

app.delete('/api/v1/rules/:id', requireVerified, (req, res) => {
  const index = mockData.rules.findIndex(r => r.id === req.params.id);
  if (index > -1) mockData.rules.splice(index, 1);
  res.json(apiResponse({ success: true }));
});

app.patch('/api/v1/rules/:id', requireVerified, (req, res) => {
  const rule = mockData.rules.find(r => r.id === req.params.id);
  if (!rule) return res.status(404).json({ success: false, error: 'Rule not found' });
  rule.status = req.body.status;
  res.json(apiResponse(rule));
});

app.get('/api/v1/rules/templates', (req, res) => {
  res.json(apiResponse(mockData.ruleTemplates));
});

// ==================== API KEYS (Protected by verification) ====================
app.get('/api/v1/api-keys', requireVerified, (req, res) => {
  res.json(apiResponse(mockData.apiKeys));
});

app.post('/api/v1/api-keys', requireVerified, (req, res) => {
  const newKey = {
    id: `key_${Date.now()}`,
    keyPrefix: `ag_${Math.random().toString(36).substring(2, 8)}`,
    status: 'active',
    createdAt: new Date().toISOString(),
    ...req.body,
  };
  mockData.apiKeys.push(newKey);
  res.json(apiResponse({
    apiKey: newKey,
    fullKey: `${newKey.keyPrefix}.${Math.random().toString(36).substring(2, 30)}`,
  }));
});

app.post('/api/v1/api-keys/:id/rotate', requireVerified, (req, res) => {
  const oldKey = mockData.apiKeys.find(k => k.id === req.params.id);
  if (!oldKey) return res.status(404).json({ success: false, error: 'Key not found' });
  
  const { gracePeriodHours = 24, revokeOldImmediately = false } = req.body;
  
  oldKey.status = revokeOldImmediately ? 'revoked' : 'rotating';
  oldKey.gracePeriodEndsAt = revokeOldImmediately 
    ? undefined 
    : new Date(Date.now() + gracePeriodHours * 3600000).toISOString();
  
  const newKey = {
    id: `key_${Date.now()}`,
    name: oldKey.name,
    keyPrefix: `ag_${Math.random().toString(36).substring(2, 8)}`,
    status: 'active',
    createdAt: new Date().toISOString(),
    permissions: oldKey.permissions,
    rotatedFromId: oldKey.id,
    agentId: oldKey.agentId,
  };
  
  oldKey.rotatedToId = newKey.id;
  mockData.apiKeys.push(newKey);
  
  res.json(apiResponse({
    oldKey,
    newKey,
    fullKey: `${newKey.keyPrefix}.${Math.random().toString(36).substring(2, 30)}`,
    gracePeriodEndsAt: oldKey.gracePeriodEndsAt,
  }));
});

app.post('/api/v1/api-keys/:id/revoke', requireVerified, (req, res) => {
  const key = mockData.apiKeys.find(k => k.id === req.params.id);
  if (key) {
    key.status = 'revoked';
    key.revokedAt = new Date().toISOString();
  }
  res.json(apiResponse(key));
});

app.post('/api/v1/api-keys/:id/extend-grace', requireVerified, (req, res) => {
  const key = mockData.apiKeys.find(k => k.id === req.params.id);
  if (key && key.gracePeriodEndsAt) {
    const hours = req.body.hours || 24;
    key.gracePeriodEndsAt = new Date(
      new Date(key.gracePeriodEndsAt).getTime() + hours * 3600000
    ).toISOString();
  }
  res.json(apiResponse(key));
});

app.get('/api/v1/api-keys/:id/rotation-chain', requireVerified, (req, res) => {
  const key = mockData.apiKeys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ success: false, error: 'Key not found' });
  
  const chain = [key];
  let current = key;
  while (current.rotatedFromId) {
    const prev = mockData.apiKeys.find(k => k.id === current.rotatedFromId);
    if (prev) {
      chain.unshift(prev);
      current = prev;
    } else break;
  }
  
  res.json(apiResponse(chain));
});

// ==================== QUOTA ====================
app.get('/api/v1/quota/usage', (req, res) => {
  res.json(apiResponse(mockData.quotaUsage));
});

app.get('/api/v1/quota/rate-limit', (req, res) => {
  res.json(apiResponse({
    remaining: 8472,
    limit: 10000,
    resetAt: new Date(Date.now() + 3600000).toISOString(),
  }));
});

// ==================== SETTINGS ====================
app.get('/api/v1/tenant/notifications', (req, res) => {
  res.json(apiResponse(mockData.notificationSettings));
});

app.get('/api/v1/tenant/pii', (req, res) => {
  res.json(apiResponse(mockData.piiSettings));
});

// ==================== WEBSOCKET ====================
wss.on('connection', (ws, req) => {
  console.log('WebSocket client connected');
  
  const url = new URL(req.url, 'http://localhost');
  const agentId = url.searchParams.get('agent_id');
  
  // Send initial stats
  ws.send(JSON.stringify({
    type: 'stats',
    data: mockData.dashboardStats,
    timestamp: new Date().toISOString(),
  }));
  
  // Simulate real-time events
  const interval = setInterval(() => {
    if (ws.readyState === 1) {
      const event = generateRandomEvent(agentId);
      ws.send(JSON.stringify({
        type: 'event',
        payload: event,
        timestamp: new Date().toISOString(),
      }));
    }
  }, 2000); // Send event every 2 seconds
  
  ws.on('close', () => {
    console.log('WebSocket client disconnected');
    clearInterval(interval);
  });
});

function generateRandomEvent(agentId) {
  const actions = ['blocked', 'allowed', 'flagged'];
  const severities = ['critical', 'high', 'medium', 'low'];
  const paths = ['/api/users', '/api/query', '/health', '/api/login', '/api/data'];
  const agents = mockData.agents;
  
  const agent = agentId 
    ? agents.find(a => a.id === agentId) || agents[0]
    : agents[Math.floor(Math.random() * agents.length)];
  
  return {
    id: `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
    timestamp: new Date().toISOString(),
    action: actions[Math.floor(Math.random() * actions.length)],
    severity: severities[Math.floor(Math.random() * severities.length)],
    ruleId: `rule_${Math.floor(Math.random() * 5) + 1}`,
    ruleName: ['SQL Injection', 'XSS Prevention', 'Rate Limit', 'PII Detection', 'Auth Check'][Math.floor(Math.random() * 5)],
    agentId: agent?.id,
    agentName: agent?.name,
    clientIp: `192.168.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`,
    userAgent: 'Mozilla/5.0...',
    path: paths[Math.floor(Math.random() * paths.length)],
    method: ['GET', 'POST', 'PUT', 'DELETE'][Math.floor(Math.random() * 4)],
    latencyMs: Math.floor(Math.random() * 100) + 5,
    traceId: `trace_${Math.random().toString(36).substr(2, 16)}`,
    details: {},
  };
}

// ==================== START SERVER ====================
const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
  console.log(`🚀 AxiomGuard Mock API Server running on http://localhost:${PORT}`);
  console.log(`📊 Dashboard: http://localhost:${PORT}/api/v1/dashboard/stats`);
  console.log(`🔌 WebSocket: ws://localhost:${PORT}/ws/events`);
  console.log(`\n🔐 Security Features Enabled:`);
  console.log(`   • Rate limiting: ${RATE_LIMIT_MAX} attempts per ${RATE_LIMIT_WINDOW/60000} minutes`);
  console.log(`   • Honeypot bot protection`);
  console.log(`   • Deferred email verification (24h grace period)`);
  console.log(`   • Automatic unverified account cleanup`);
});
