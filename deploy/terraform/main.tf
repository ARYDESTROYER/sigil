# Hetzner Cloud VM + firewall for sigild. SKELETON — NOT APPLIED.
# Provisioning is gated on the Hetzner identity check clearing (Day 0). Run
# `terraform init && terraform plan` only after setting hcloud_token via a
# *.tfvars sourced from the team password manager (never committed).

terraform {
  required_version = ">= 1.6"
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.48"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

resource "hcloud_server" "sigild" {
  name        = "sigild-1"
  server_type = var.server_type # e.g. cx22 / ccx13
  image       = "ubuntu-24.04"
  location    = var.location # e.g. fsn1 (Falkenstein)
  ssh_keys    = var.ssh_key_names

  labels = {
    app   = "sigild"
    stage = "prelaunch"
  }
}

# Inbound: 22 (founder IPs only), 80 + 443. Everything else denied.
resource "hcloud_firewall" "sigild" {
  name = "sigild-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22"
    source_ips = var.admin_cidrs
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "80"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "sigild" {
  firewall_id = hcloud_firewall.sigild.id
  server_ids  = [hcloud_server.sigild.id]
}

output "sigild_ipv4" {
  value = hcloud_server.sigild.ipv4_address
}
