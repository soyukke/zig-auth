terraform {
  required_version = ">= 1.0"

  backend "local" {
    path = "terraform.tfstate"
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

module "auth" {
  source = "../../modules/cloudflare-auth"

  account_id         = var.cloudflare_account_id
  environment        = "prod"
  worker_script_name = "zig-auth"

  github_client_id     = var.github_client_id
  github_client_secret = var.github_client_secret
  google_client_id     = var.google_client_id
  google_client_secret = var.google_client_secret
}

output "d1_database_id" {
  value = module.auth.d1_database_id
}

output "kv_namespace_id" {
  value = module.auth.kv_namespace_id
}
