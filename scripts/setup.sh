#!/usr/bin/env bash
set -euo pipefail

echo "=== zig-auth setup ==="
echo ""

# Check wrangler login
if ! npx wrangler whoami &>/dev/null; then
  echo "Cloudflare にログインしてください:"
  npx wrangler login
fi

SUBDOMAIN=$(npx wrangler whoami 2>&1 | grep -oP '(?<=│ )\S+(?=@)' || echo "your-subdomain")

echo ""
echo "D1 データベースと KV namespace を作成します..."
echo ""

# Dev
echo "--- dev ---"
D1_DEV=$(npx wrangler d1 create zig-auth-dev 2>&1)
D1_DEV_ID=$(echo "$D1_DEV" | grep 'database_id' | awk '{print $3}')
echo "D1 dev: $D1_DEV_ID"

KV_DEV=$(npx wrangler kv namespace create SESSIONS_KV 2>&1)
KV_DEV_ID=$(echo "$KV_DEV" | grep '^id' | awk '{print $3}' || echo "$KV_DEV" | grep -oP 'id = "\K[^"]+')
echo "KV dev: $KV_DEV_ID"

# Staging
echo "--- staging ---"
D1_STG=$(npx wrangler d1 create zig-auth-staging 2>&1)
D1_STG_ID=$(echo "$D1_STG" | grep 'database_id' | awk '{print $3}')
echo "D1 staging: $D1_STG_ID"

KV_STG=$(npx wrangler kv namespace create SESSIONS_KV_STAGING 2>&1)
KV_STG_ID=$(echo "$KV_STG" | grep '^id' | awk '{print $3}' || echo "$KV_STG" | grep -oP 'id = "\K[^"]+')
echo "KV staging: $KV_STG_ID"

# Production
echo "--- production ---"
D1_PROD=$(npx wrangler d1 create zig-auth-prod 2>&1)
D1_PROD_ID=$(echo "$D1_PROD" | grep 'database_id' | awk '{print $3}')
echo "D1 prod: $D1_PROD_ID"

KV_PROD=$(npx wrangler kv namespace create SESSIONS_KV_PROD 2>&1)
KV_PROD_ID=$(echo "$KV_PROD" | grep '^id' | awk '{print $3}' || echo "$KV_PROD" | grep -oP 'id = "\K[^"]+')
echo "KV prod: $KV_PROD_ID"

# Generate wrangler.toml
echo ""
echo "wrangler.toml を生成しています..."

sed \
  -e "s/<YOUR_D1_DEV_DATABASE_ID>/$D1_DEV_ID/" \
  -e "s/<YOUR_KV_DEV_NAMESPACE_ID>/$KV_DEV_ID/" \
  -e "s/<YOUR_D1_STAGING_DATABASE_ID>/$D1_STG_ID/" \
  -e "s/<YOUR_KV_STAGING_NAMESPACE_ID>/$KV_STG_ID/" \
  -e "s/<YOUR_D1_PROD_DATABASE_ID>/$D1_PROD_ID/" \
  -e "s/<YOUR_KV_PROD_NAMESPACE_ID>/$KV_PROD_ID/" \
  -e "s/<YOUR_SUBDOMAIN>/$SUBDOMAIN/g" \
  wrangler.toml.example > wrangler.toml

echo ""
echo "=== セットアップ完了 ==="
echo ""
echo "次のステップ:"
echo "  1. JWT シークレットを設定: npx wrangler secret put JWT_SECRET"
echo "  2. ローカル開発: npx wrangler dev"
echo "  3. デプロイ: npx wrangler deploy --env staging"
