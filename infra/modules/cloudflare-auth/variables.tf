variable "account_id" {
  description = "Cloudflare account ID"
  type        = string
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "zig-auth"
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
}

variable "worker_script_name" {
  description = "Name of the Workers script (must exist before applying secrets)"
  type        = string
}

variable "github_client_id" {
  description = "GitHub OAuth App Client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "github_client_secret" {
  description = "GitHub OAuth App Client Secret"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_client_id" {
  description = "Google OAuth Client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_client_secret" {
  description = "Google OAuth Client Secret"
  type        = string
  default     = ""
  sensitive   = true
}
