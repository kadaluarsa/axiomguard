#!/usr/bin/env node
const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

const binaryName = os.platform() === 'win32' ? 'axiomguard-mcp.exe' : 'axiomguard-mcp';
const binaryPath = path.join(__dirname, 'bin', binaryName);

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  shell: false,
});

child.on('exit', (code) => {
  process.exit(code ?? 0);
});
