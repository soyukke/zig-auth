# zig-auth justfile

# デフォルト: レシピ一覧
default:
    @just --list

# ── 開発 ──

# Worker + フロントエンドを同時に起動
dev:
    npx wrangler dev & \
    cd web && npm run dev & \
    wait

# Worker のみ起動
dev-worker:
    npx wrangler dev

# フロントエンドのみ起動
dev-web:
    cd web && npm run dev

# ── ビルド ──

# Zig WASM をビルド
build-wasm:
    zig build -Doptimize=ReleaseSmall && cp zig-out/bin/zig-auth.wasm worker/

# フロントエンドをビルド
build-web:
    cd web && npm run build

# 全ビルド
build: build-wasm build-web

# ── テスト ──

# Zig ユニットテスト
test:
    zig build test

# ── DB ──

# ローカル DB にマイグレーション適用
db-migrate:
    npx wrangler d1 migrations apply zig-auth-dev --local

# リモート DB にマイグレーション適用
db-migrate-remote env="":
    npx wrangler d1 migrations apply zig-auth-dev --remote {{ if env != "" { "--env " + env } else { "" } }}

# ── デプロイ ──

# staging にデプロイ
deploy-staging: build-wasm
    npx wrangler deploy --env staging

# production にデプロイ
deploy-prod: build-wasm
    npx wrangler deploy --env production

# ── セットアップ ──

# 初期セットアップ (D1/KV 作成 + wrangler.toml 生成)
setup:
    ./scripts/setup.sh

# npm 依存インストール
install:
    npm install && cd web && npm install

# ── セキュリティ ──

# gitleaks でシークレットスキャン
scan:
    gitleaks detect --source . --no-git -v
