const { computeHash: _computeHash, verifyToken: _verifyToken, verifyTokenWithChecks: _verifyTokenWithChecks } = require('./axiomguard.node');

class CircuitBreaker {
  constructor({ failureThreshold = 5, recoveryTimeout = 30000 } = {}) {
    this._failureCount = 0;
    this._failureThreshold = failureThreshold;
    this._recoveryTimeout = recoveryTimeout;
    this._lastFailureTime = null;
    this._state = 'closed';
  }

  recordSuccess() {
    this._failureCount = 0;
    this._state = 'closed';
  }

  recordFailure() {
    this._failureCount++;
    this._lastFailureTime = Date.now();
    if (this._failureCount >= this._failureThreshold) {
      this._state = 'open';
    }
  }

  get allowsRequest() {
    if (this._state === 'closed') return true;
    if (this._state === 'open') {
      if (this._lastFailureTime && (Date.now() - this._lastFailureTime > this._recoveryTimeout)) {
        this._state = 'half-open';
        return true;
      }
      return false;
    }
    return true;
  }
}

async function retryFetch(url, options, { maxRetries = 3, baseDelay = 100, circuitBreaker = null } = {}) {
  if (circuitBreaker && !circuitBreaker.allowsRequest) {
    throw new Error('Circuit breaker is open — control plane unavailable');
  }

  let lastError;
  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const resp = await fetch(url, options);
      if (resp.status >= 500) {
        const err = new Error(`Server error: ${resp.status}`);
        lastError = err;
        if (circuitBreaker) circuitBreaker.recordFailure();
        if (attempt < maxRetries - 1) {
          await new Promise(r => setTimeout(r, baseDelay * Math.pow(2, attempt)));
        }
        continue;
      }
      if (circuitBreaker) circuitBreaker.recordSuccess();
      return resp;
    } catch (err) {
      lastError = err;
      if (circuitBreaker) circuitBreaker.recordFailure();
      if (attempt < maxRetries - 1) {
        await new Promise(r => setTimeout(r, baseDelay * Math.pow(2, attempt)));
      }
    }
  }
  throw new Error(`Control plane request failed after ${maxRetries} retries: ${lastError?.message}`);
}

class GuardResult {
  constructor({ decision, reason, riskScore, token, tool, agentId, sessionId }) {
    this.decision = decision;
    this.reason = reason;
    this.riskScore = riskScore;
    this.token = token;
    this.tool = tool;
    this.agentId = agentId;
    this.sessionId = sessionId;
  }

  get allowed() {
    return this.decision === 'Allow';
  }

  [Symbol.for('nodejs.util.inspect.custom')]() {
    return `GuardResult(decision='${this.decision}', tool='${this.tool}', agentId='${this.agentId}', risk=${this.riskScore.toFixed(2)})`;
  }
}

class Guard {
  constructor({ cpUrl, apiKey, tenantId, agentId, verifyingKeyHex, timeout = 5000, maxRetries = 3, circuitBreaker } = {}) {
    this.cpUrl = cpUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    this.agentId = agentId;
    this.verifyingKeyHex = verifyingKeyHex;
    this.timeout = timeout;
    this.maxRetries = maxRetries;
    this.circuitBreaker = circuitBreaker || new CircuitBreaker();
  }

  async check(tool, args, { sessionId, agentId } = {}) {
    const effectiveAgent = agentId || this.agentId || 'default';
    const effectiveSession = sessionId || `node-${Date.now()}`;
    const argsJson = JSON.stringify(args, Object.keys(args).sort());
    const argsHash = _computeHash(argsJson);

    const body = JSON.stringify({
      tool,
      args_hash: argsHash,
      session_id: effectiveSession,
      tenant_id: this.tenantId,
      agent_id: effectiveAgent,
      decision: 'Allow',
      risk_score: 0.0,
    });

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const resp = await retryFetch(`${this.cpUrl}/v1/token/issue`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': this.apiKey,
          'X-Tenant-ID': this.tenantId,
        },
        body,
        signal: controller.signal,
      }, {
        maxRetries: this.maxRetries,
        circuitBreaker: this.circuitBreaker,
      });

      if (!resp.ok) {
        if (resp.status === 401) {
          throw new Error('AxiomGuard blocked tool call: authentication failed');
        }
        if (resp.status === 429) {
          throw new Error('AxiomGuard blocked tool call: rate limited');
        }
        if (resp.status >= 400) {
          throw new Error(`AxiomGuard blocked tool call: CP returned ${resp.status}`);
        }
        const text = await resp.text();
        throw new Error(`Control plane returned ${resp.status}: ${text}`);
      }

      const data = await resp.json();
      const token = data.token || null;
      return new GuardResult({
        decision: token ? 'Allow' : 'Block',
        reason: token ? '' : 'No token issued',
        riskScore: 0,
        token,
        tool,
        agentId: effectiveAgent,
        sessionId: effectiveSession,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }
}

function computeHash(argsObj) {
  return _computeHash(JSON.stringify(argsObj));
}

function verifyToken(tokenStr, verifyingKeyHex) {
  return _verifyToken(tokenStr, verifyingKeyHex);
}

function verifyTokenWithChecks(tokenStr, verifyingKeyHex, { expectedTool, expectedAgentId, expectedArgs, maxRisk } = {}) {
  return _verifyTokenWithChecks(
    tokenStr,
    verifyingKeyHex,
    expectedTool || null,
    expectedAgentId || null,
    expectedArgs ? JSON.stringify(expectedArgs) : null,
    maxRisk ?? null,
  );
}

module.exports = {
  Guard,
  GuardResult,
  CircuitBreaker,
  computeHash,
  verifyToken,
  verifyTokenWithChecks,
};
