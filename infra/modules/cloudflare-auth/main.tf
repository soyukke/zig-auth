terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

# D1 Database
resource "cloudflare_d1_database" "auth_db" {
  account_id = var.account_id
  name       = "${var.project_name}-${var.environment}"
}

# KV Namespace for sessions
resource "cloudflare_workers_kv_namespace" "sessions" {
  account_id = var.account_id
  title      = "${var.project_name}-sessions-${var.environment}"
}

# JWT Secret
resource "random_password" "jwt_secret" {
  length  = 64
  special = true
}

resource "cloudflare_workers_secret" "jwt_secret" {
  account_id  = var.account_id
  script_name = var.worker_script_name
  secret_name = "JWT_SECRET"
  secret_text = random_password.jwt_secret.result
}

# OAuth Secrets (optional, set via variables)
resource "cloudflare_workers_secret" "github_client_id" {
  count       = var.github_client_id != "" ? 1 : 0
  account_id  = var.account_id
  script_name = var.worker_script_name
  secret_name = "GITHUB_CLIENT_ID"
  secret_text = var.github_client_id
}

resource "cloudflare_workers_secret" "github_client_secret" {
  count       = var.github_client_secret != "" ? 1 : 0
  account_id  = var.account_id
  script_name = var.worker_script_name
  secret_name = "GITHUB_CLIENT_SECRET"
  secret_text = var.github_client_secret
}

resource "cloudflare_workers_secret" "google_client_id" {
  count       = var.google_client_id != "" ? 1 : 0
  account_id  = var.account_id
  script_name = var.worker_script_name
  secret_name = "GOOGLE_CLIENT_ID"
  secret_text = var.google_client_id
}

resource "cloudflare_workers_secret" "google_client_secret" {
  count       = var.google_client_secret != "" ? 1 : 0
  account_id  = var.account_id
  script_name = var.worker_script_name
  secret_name = "GOOGLE_CLIENT_SECRET"
  secret_text = var.google_client_secret
}
