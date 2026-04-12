# sdk-node-runtime
Node.js official runtime wrapper for AxiomGuard Guard.

This package provides:
- Guard class: communicates with Control Plane via /v1/token/issue
- RuntimeGuard: wraps Guard with auto background loops for audit flush and policy refresh

Usage:

```
const { Guard, RuntimeGuard } = require('sdk-node-runtime');

const guard = new Guard({
  cpUrl: 'https://cp.example.com',
  apiKey: 'your_api_key',
  tenantId: 'tenant-1',
  agentId: 'agent-1',
  timeout: 5000
});

guard.check('tool-name', { foo: 'bar' }, { sessionId: 'sess-1' })
  .then(res => console.log(res))
  .catch(err => console.error(err));
```

Runtime usage:
```
const rt = new RuntimeGuard({
  cpUrl: 'https://cp.example.com',
  apiKey: 'your_api_key',
  tenantId: 'tenant-1',
  agentId: 'agent-1',
});
rt.start();
// After some time, you can stop
// rt.stop();
```
