variable "location" {
  description = "Azure region (Central India is the closest to Mumbai)."
  type        = string
  default     = "centralindia"
}

variable "resource_group_name" {
  description = "Resource group that holds everything for this project."
  type        = string
  default     = "rg-securenotes"
}

variable "app_name" {
  description = "Name of the Container App (also the first part of its URL)."
  type        = string
  default     = "securenotes"
}

variable "image" {
  description = "Image used when the app is first created. Later releases are rolled out by the pipeline."
  type        = string
  default     = "docker.io/tanish15/securenotes:latest"
}

variable "dockerhub_username" {
  description = "Docker Hub account the image is pulled from."
  type        = string
  default     = "tanish15"
}

variable "dockerhub_token" {
  description = "Read-only Docker Hub token, so Azure pulls as a logged-in user and avoids anonymous rate limits."
  type        = string
  sensitive   = true
}

variable "alert_emails" {
  description = "Who receives 'app is down' and budget emails."
  type        = list(string)
  default     = ["tanish15@somaiya.edu", "anika.gupte@somaiya.edu"]
}

variable "github_repository" {
  description = <<-EOT
    Repository part of the GitHub OIDC subject. GitHub includes the immutable owner and repository IDs
    (owner@id/repo@id), so a deleted-and-recreated repository with the same name cannot deploy.
  EOT
  type        = string
  default     = "StarkFurry64@156516194/SecureNotes_Devops_Miniproject@1427944179"
}

variable "budget_amount" {
  description = "Monthly budget in USD for the resource group; an email is sent at 80% and 100%."
  type        = number
  default     = 10
}

variable "budget_start_date" {
  description = "First day of the month the budget starts (Azure requires the first of a month)."
  type        = string
  default     = "2026-10-01T00:00:00Z"
}

variable "enable_budget" {
  description = "Create the cost budget (set to false if the subscription type does not support budgets)."
  type        = bool
  default     = true
}
