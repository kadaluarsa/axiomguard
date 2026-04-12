#!/bin/bash
set -e

MCP_SERVER="${MCP_SERVER:-./target/release/mcp-server}"

echo "=== Testing AxiomGuard MCP Server (stdio) ==="
echo "Server binary: $MCP_SERVER"
echo ""

# Send initialize request and tools/list, then close stdin
# MCP uses newline-delimited JSON over stdio
{
  printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}'
  # Small sleep to let server process
  sleep 0.5
  printf '%s\n' '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
  sleep 0.5
} | "$MCP_SERVER" --transport stdio 2>/tmp/mcp-server-stderr.log

echo ""
echo "=== stderr output ==="
cat /tmp/mcp-server-stderr.log
