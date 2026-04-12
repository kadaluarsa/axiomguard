"use strict";

const { URL } = require('url');

class Guard {
  constructor({ cpUrl, apiKey, tenantId, agentId, timeout = 5000 }) {
    this.cpUrl = cpUrl;
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    this.agentId = agentId;
    this.timeout = timeout;
  }

  async check(tool, args, { sessionId, agentId } = {}) {
    // Resolve args hash using sdk if available, else fallback to simple hash
    const argsHash = this._computeHashSafe(args);

    // Build request body per spec
    const bodyObj = {
      tool: tool,
      args_hash: argsHash,
      session_id: sessionId || '',
      tenant_id: this.tenantId,
      agent_id: agentId || this.agentId,
      decision: 'Allow',
      risk_score: 0.0
    };

    const body = JSON.stringify(bodyObj);
    const url = this._joinPath(this.cpUrl, '/v1/token/issue');

    try {
      const { statusCode, responseText } = await this._postJsonWithRetry(url, this.apiKey, body, this.timeout, 3);
      let resp = {};
      try {
        resp = JSON.parse(responseText || '{}');
      } catch (e) {
        resp = {};
      }
      const token = resp.token;
      const decision = resp.decision || 'Allow';
      const reason = resp.reason || '';
      const riskScore = resp.risk_score ?? resp.riskScore ?? 0;
      const allowed = String(decision).toLowerCase() === 'allow';
      return {
        decision,
        reason,
        riskScore,
        token,
        tool,
        agentId: agentId || this.agentId,
        sessionId,
        allowed
      };
    } catch (err) {
      console.error('Guard.check request failed:', err);
      return {
        decision: 'Block',
        reason: err?.message || 'request failed',
        riskScore: 0,
        token: null,
        tool,
        agentId: agentId || this.agentId,
        sessionId,
        allowed: false
      };
    }
  }

  _computeHashSafe(obj) {
    // Try to use @axiomguard/sdk compute_hash if available
    try {
      const sdk = require('@axiomguard/sdk');
      if (sdk) {
        if (typeof sdk.compute_hash === 'function') {
          return sdk.compute_hash(obj);
        }
        if (typeof sdk.computeHash === 'function') {
          return sdk.computeHash(obj);
        }
      }
    } catch (e) {
      // ignore and fallback
    }
    // Fallback simple hash
    const s = JSON.stringify(obj);
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      h = ((h << 5) - h) + ch;
      h |= 0;
    }
    return Math.abs(h).toString(16);
  }

  _joinPath(base, path) {
    if (base.endsWith('/')) {
      return base + (path.startsWith('/') ? path.slice(1) : path);
    }
    return base + (path.startsWith('/') ? path : '/' + path);
  }

  async _postJsonWithRetry(url, apiKey, body, timeout, maxRetries = 3) {
    let lastError;
    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        return await this._postJson(url, apiKey, body, timeout);
      } catch (err) {
        lastError = err;
        if (attempt < maxRetries) {
          const delay = 100 * Math.pow(2, attempt);
          await new Promise(r => setTimeout(r, delay));
        }
      }
    }
    throw lastError;
  }

  async _postJson(url, apiKey, body, timeout) {
    const { URL } = require('url');
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? require('https') : require('http');
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + (parsed.search || ''),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body || '')
      }
    };
    if (apiKey) {
      options.headers['X-API-Key'] = apiKey;
    }
    return new Promise((resolve, reject) => {
      try {
        const req = lib.request(options, (res) => {
          let data = '';
          res.setEncoding('utf8');
          res.on('data', (chunk) => { data += chunk; });
          res.on('end', () => {
            resolve({ statusCode: res.statusCode, responseText: data });
          });
        });
        req.on('error', (e) => reject(e));
        if (timeout) req.setTimeout(timeout, () => { req.abort(); reject(new Error('Request timeout')); });
        req.write(body);
        req.end();
      } catch (e) {
        reject(e);
      }
    });
  }
}
