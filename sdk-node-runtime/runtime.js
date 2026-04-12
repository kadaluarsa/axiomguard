"use strict";

const Guard = require('./guard');

class RuntimeGuard {
  constructor({ cpUrl, apiKey, tenantId, agentId, timeout = 5000, flushIntervalMs = 30000, refreshPolicyMs = 300000 }) {
    this.guard = new Guard({ cpUrl, apiKey, tenantId, agentId, timeout });
    this.cpUrl = cpUrl;
    this.apiKey = apiKey;
    this.tenantId = tenantId;
    this.agentId = agentId;
    this.flushIntervalMs = flushIntervalMs;
    this.refreshPolicyMs = refreshPolicyMs;
    this.auditQueue = [];
    this.policy = null;
    this._flushTimer = null;
    this._refreshTimer = null;
    this._started = false;
  }

  start() {
    if (this._started) return;
    this._started = true;
    // flush audits periodically
    this._flushTimer = setInterval(() => {
      this._safeFlush().catch(err => console.error('Audit flush failed:', err));
    }, this.flushIntervalMs);
    // refresh policy periodically
    this._refreshTimer = setInterval(() => {
      this._safeRefresh().catch(err => console.error('Policy refresh failed:', err));
    }, this.refreshPolicyMs);
    // initial run
    this._safeFlush().catch(() => {});
    this._safeRefresh().catch(() => {});
  }

  stop() {
    if (this._flushTimer) {
      clearInterval(this._flushTimer);
      this._flushTimer = null;
    }
    if (this._refreshTimer) {
      clearInterval(this._refreshTimer);
      this._refreshTimer = null;
    }
    this._started = false;
  }

  async check(tool, args, { sessionId, agentId } = {}) {
    const res = await this.guard.check(tool, args, { sessionId, agentId: agentId || this.agentId });
    // enqueue audit event
    const effectiveAgentId = agentId || this.agentId;
    const argsHash = this._hashArgs(args);
    const event = {
      tool: tool,
      args_hash: argsHash,
      session_id: sessionId || '',
      tenant_id: this.tenantId,
      agent_id: effectiveAgentId,
      decision: res.decision || 'Allow',
      risk_score: res.riskScore ?? 0
    };
    this.auditQueue.push(event);
    return res;
  }

  _hashArgs(args) {
    // try to reuse same hashing as Guard
    try {
      const sdk = require('@axiomguard/sdk');
      if (sdk) {
        if (typeof sdk.compute_hash === 'function') return sdk.compute_hash(args);
        if (typeof sdk.computeHash === 'function') return sdk.computeHash(args);
      }
    } catch (e) {
      // ignore
    }
    const s = JSON.stringify(args);
    let h = 0;
    for (let i = 0; i < s.length; i++) {
      const ch = s.charCodeAt(i);
      h = ((h << 5) - h) + ch;
      h |= 0;
    }
    return Math.abs(h).toString(16);
  }

  async _safeFlush() {
    if (!this.auditQueue.length) return;
    const events = this.auditQueue.splice(0);
    const url = this.cpUrl.endsWith('/') ? this.cpUrl + 'v1/audit/batch' : this.cpUrl + '/v1/audit/batch';
    const body = JSON.stringify({ events });
    try {
      await this._postJson(url, this.apiKey, body, 5000);
    } catch (e) {
      console.error('Failed to flush audit events:', e);
      // On failure, requeue events at head
      this.auditQueue.unshift(...events);
    }
  }

  async _safeRefresh() {
    const url = this.cpUrl.endsWith('/') ? this.cpUrl + 'v1/policy/pull' : this.cpUrl + '/v1/policy/pull';
    const body = JSON.stringify({ agent_id: this.agentId });
    try {
      const res = await this._postJson(url, this.apiKey, body, 5000);
      // parse
      if (res && res.statusCode >= 200 && res.statusCode < 300) {
        try {
          const parsed = JSON.parse(res.responseText);
          this.policy = parsed;
        } catch (e) {
          this.policy = res.responseText;
        }
      } else {
        console.error('Policy pull failed with status', res.statusCode);
      }
    } catch (e) {
      console.error('Policy pull error:', e);
    }
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
    if (apiKey) options.headers['X-API-Key'] = apiKey;
    return new Promise((resolve, reject) => {
      const req = lib.request(options, (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => data += chunk);
        res.on('end', () => resolve({ statusCode: res.statusCode, responseText: data }));
      });
      req.on('error', (e) => reject(e));
      if (timeout) req.setTimeout(timeout, () => { req.abort(); reject(new Error('Request timeout')); });
      req.write(body);
      req.end();
    });
  }
}

module.exports = RuntimeGuard;
