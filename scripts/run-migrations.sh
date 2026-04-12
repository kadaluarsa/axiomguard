#!/bin/bash
# AxiomGuard Database Migration Runner
# Usage: ./run-migrations.sh <DATABASE_URL>

set -e

DATABASE_URL="${1:-$DATABASE_URL}"

if [ -z "$DATABASE_URL" ]; then
    echo "Error: DATABASE_URL not provided"
    echo "Usage: ./run-migrations.sh 'postgres://user:pass@host:5432/dbname'"
    exit 1
fi

echo "🔄 Running AxiomGuard database migrations..."
echo "================================================"

# Check if psql is available
if ! command -v psql &> /dev/null; then
    echo "Error: psql not found. Please install PostgreSQL client."
    exit 1
fi

# Run migrations in order
echo "📦 Migration 001: Initial schema..."
psql "$DATABASE_URL" -f common/migrations/001_initial_schema.sql

echo "📦 Migration 002: Production schema..."
psql "$DATABASE_URL" -f common/migrations/002_production_schema.sql

echo "================================================"
echo "✅ All migrations completed successfully!"
echo ""
echo "Next steps:"
echo "  1. Deploy Shield service: fly deploy --app axiomguard-shield"
echo "  2. Set secrets: fly secrets set DATABASE_URL='$DATABASE_URL' --app axiomguard-shield"
echo "  3. Verify: fly logs --app axiomguard-shield"
