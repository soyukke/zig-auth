output "d1_database_id" {
  description = "D1 database ID (use in wrangler.toml)"
  value       = cloudflare_d1_database.auth_db.id
}

output "kv_namespace_id" {
  description = "KV namespace ID (use in wrangler.toml)"
  value       = cloudflare_workers_kv_namespace.sessions.id
}

output "d1_database_name" {
  description = "D1 database name"
  value       = cloudflare_d1_database.auth_db.name
}
