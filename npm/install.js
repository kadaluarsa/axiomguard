#!/usr/bin/env node
const https = require('https');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const VERSION = require('./package.json').version;
const REPO = 'axiomguard/axiomguard';
const BIN_DIR = path.join(__dirname, 'bin');

function getPlatform() {
  const platform = os.platform();
  const arch = os.arch();
  const map = {
    'darwin-x64': 'darwin-x64',
    'darwin-arm64': 'darwin-arm64',
    'linux-x64': 'linux-x64',
    'linux-arm64': 'linux-arm64',
    'win32-x64': 'windows-x64',
  };
  const key = `${platform}-${arch}`;
  return map[key] || null;
}

function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, { followRedirect: true }, (response) => {
      if (response.statusCode === 301 || response.statusCode === 302) {
        downloadFile(response.headers.location, dest).then(resolve).catch(reject);
        return;
      }
      if (response.statusCode !== 200) {
        reject(new Error(`Download failed with status ${response.statusCode}: ${url}`));
        return;
      }
      response.pipe(file);
      file.on('finish', () => {
        file.close(resolve);
      });
    }).on('error', reject);
  });
}

async function main() {
  const platform = getPlatform();
  if (!platform) {
    console.warn(`[axiomguard-mcp] Unsupported platform: ${os.platform()}-${os.arch()}`);
    console.warn(`[axiomguard-mcp] You can build from source: cargo build --release -p mcp-server`);
    process.exit(0);
  }

  const binaryName = platform.startsWith('windows') ? 'axiomguard-mcp.exe' : 'axiomguard-mcp';
  const assetName = `axiomguard-mcp-${platform}`;
  const binaryPath = path.join(BIN_DIR, binaryName);

  if (fs.existsSync(binaryPath)) {
    console.log(`[axiomguard-mcp] Binary already exists: ${binaryPath}`);
    return;
  }

  // Check if we're in development (repo root has Cargo.toml)
  const repoRoot = path.join(__dirname, '..');
  const cargoToml = path.join(repoRoot, 'Cargo.toml');
  if (fs.existsSync(cargoToml)) {
    console.log(`[axiomguard-mcp] Development mode detected. Building from source...`);
    try {
      execSync('cargo build --release -p mcp-server', { cwd: repoRoot, stdio: 'inherit' });
      const builtBinary = path.join(repoRoot, 'target', 'release', binaryName);
      fs.copyFileSync(builtBinary, binaryPath);
      fs.chmodSync(binaryPath, 0o755);
      console.log(`[axiomguard-mcp] Built and installed: ${binaryPath}`);
      return;
    } catch (e) {
      console.error(`[axiomguard-mcp] Build failed: ${e.message}`);
      process.exit(1);
    }
  }

  const url = `https://github.com/${REPO}/releases/download/mcp-server-v${VERSION}/${assetName}`;
  console.log(`[axiomguard-mcp] Downloading ${assetName} (v${VERSION})...`);

  fs.mkdirSync(BIN_DIR, { recursive: true });

  try {
    await downloadFile(url, binaryPath);
    fs.chmodSync(binaryPath, 0o755);
    console.log(`[axiomguard-mcp] Installed: ${binaryPath}`);
  } catch (err) {
    console.error(`[axiomguard-mcp] Download failed: ${err.message}`);
    console.error(`[axiomguard-mcp] You can manually download the binary from:`);
    console.error(`  ${url}`);
    console.error(`[axiomguard-mcp] Or build from source: cargo build --release -p mcp-server`);
    process.exit(1);
  }
}

main();
