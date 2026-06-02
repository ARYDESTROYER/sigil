# Variables for the sigild Hetzner skeleton. Provide values via a *.tfvars file
# sourced from the team password manager (gitignored — never commit secrets).

variable "hcloud_token" {
  description = "Hetzner Cloud API token"
  type        = string
  sensitive   = true
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "cx22"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "fsn1"
}

variable "ssh_key_names" {
  description = "Names of SSH keys already uploaded to the Hetzner project"
  type        = list(string)
  default     = []
}

variable "admin_cidrs" {
  description = "Founder source CIDRs allowed to reach SSH (port 22)"
  type        = list(string)
  default     = []
}
